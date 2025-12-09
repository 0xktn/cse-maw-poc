# Host Worker Setup

This guide covers setting up the untrusted host application that runs the Temporal worker and communicates with the enclave via vsock.

## Overview

The host worker is the "Untrusted" component that:
1. Runs Temporal activities and workflows
2. Communicates with the enclave via vsock
3. Passes encrypted data (ciphertext) between Temporal and the enclave
4. Never sees plaintext data

```
┌─────────────────────────────────────────────────────────────┐
│                        Host (EC2)                           │
│  ┌──────────────────┐    ┌─────────────────┐               │
│  │  Temporal Worker │◄──►│ Temporal Server │               │
│  │  ┌────────────┐  │    └─────────────────┘               │
│  │  │ Activities │  │                                       │
│  │  └─────┬──────┘  │                                       │
│  └────────┼─────────┘                                       │
│           │ vsock                                           │
│  ┌────────▼─────────┐                                       │
│  │     Enclave      │                                       │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Python 3.9+ installed
- Temporal server accessible (Cloud or self-hosted)
- Enclave running and listening on vsock port 5000

## Project Structure

```
host/
├── requirements.txt     # Python dependencies
├── worker.py           # Temporal worker entry point
├── activities.py       # Enclave communication activities
├── workflows.py        # Workflow definitions
├── vsock_client.py     # vsock client utilities
└── config.py           # Configuration settings
```

## Step 1: Install Dependencies

```txt
# host/requirements.txt
temporalio>=1.3.0
protobuf>=4.24.0
python-dotenv>=1.0.0
```

Install dependencies:

```bash
cd host
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Step 2: Create Configuration

```python
# host/config.py
import os
from dotenv import load_dotenv

load_dotenv()

# Temporal configuration
TEMPORAL_HOST = os.getenv("TEMPORAL_HOST", "localhost:7233")
TEMPORAL_NAMESPACE = os.getenv("TEMPORAL_NAMESPACE", "confidential-workflow-poc")
TEMPORAL_TASK_QUEUE = os.getenv("TEMPORAL_TASK_QUEUE", "confidential-workflow-queue")

# TLS configuration (for Temporal Cloud)
TEMPORAL_TLS_ENABLED = os.getenv("TEMPORAL_TLS_ENABLED", "false").lower() == "true"
TEMPORAL_TLS_CERT_PATH = os.getenv("TEMPORAL_TLS_CERT_PATH", "./certs/client.pem")
TEMPORAL_TLS_KEY_PATH = os.getenv("TEMPORAL_TLS_KEY_PATH", "./certs/client.key")

# Enclave configuration
ENCLAVE_CID = int(os.getenv("ENCLAVE_CID", "16"))  # Enclave CID from nitro-cli
ENCLAVE_PORT = int(os.getenv("ENCLAVE_PORT", "5000"))
```

Configuration is managed via environment variables passed by the startup scripts (`scripts/run-worker-ssm.sh`). You do not need to create a `.env` file manually.


## Step 3: Implement vsock Client

```python
# host/vsock_client.py
import socket
import json
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

class VsockClient:
    """Client for communicating with the enclave via vsock."""
    
    def __init__(self, cid: int, port: int):
        self.cid = cid
        self.port = port
    
    def send_request(self, mode: str, payload: Any) -> Dict:
        """
        Send a request to the enclave and receive response.
        
        Args:
            mode: 'A' or 'B' for agent mode
            payload: Data to send (will be JSON serialized)
            
        Returns:
            Response from enclave
        """
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        
        try:
            sock.connect((self.cid, self.port))
            logger.info(f"Connected to enclave CID:{self.cid} Port:{self.port}")
            
            # Prepare request
            request = {
                'type': 'process',
                'payload': payload
            }
            data = json.dumps(request).encode('utf-8')
            
            # Send length + data
            sock.sendall(len(data).to_bytes(4, 'big'))
            sock.sendall(data)
            
            # Receive response
            length_bytes = sock.recv(4)
            response_length = int.from_bytes(length_bytes, 'big')
            
            response_data = b''
            while len(response_data) < response_length:
                chunk = sock.recv(min(4096, response_length - len(response_data)))
                if not chunk:
                    break
                response_data += chunk
            
            return json.loads(response_data.decode('utf-8'))
            
        except socket.error as e:
            logger.error(f"vsock error: {e}")
            raise
        finally:
            sock.close()


# For local testing without enclave
class MockVsockClient:
    """Mock client for testing without actual enclave."""
    
    def __init__(self, cid: int, port: int):
        self.cid = cid
        self.port = port
    
    def send_request(self, mode: str, payload: Any) -> Dict:
        """Return mock encrypted data."""
        import hashlib
        mock_ciphertext = hashlib.sha256(
            f"{mode}:{payload}".encode()
        ).hexdigest()
        
        return {
            'status': 'success',
            'ciphertext': mock_ciphertext
        }
```

## Step 4: Implement Activities

```python
# host/activities.py
from temporalio import activity
from dataclasses import dataclass
from typing import Optional
import logging

from config import ENCLAVE_CID, ENCLAVE_PORT
from vsock_client import VsockClient

logger = logging.getLogger(__name__)


@dataclass
class EnclaveInput:
    """Input for enclave activity."""
    mode: str  # 'A' or 'B'
    payload: Optional[str] = None  # For mode A: initial input, for mode B: ciphertext


@dataclass
class EnclaveOutput:
    """Output from enclave activity."""
    ciphertext: str
    status: str


@activity.defn
async def secure_enclave_activity(input: EnclaveInput) -> EnclaveOutput:
    """
    Activity that communicates with the enclave.
    This is the only point of interaction with encrypted data.
    """
    activity.logger.info(f"Executing enclave activity in mode {input.mode}")
    
    client = VsockClient(ENCLAVE_CID, ENCLAVE_PORT)
    
    try:
        response = client.send_request(input.mode, input.payload)
        
        if response.get('status') != 'ok':
            raise RuntimeError(f"Enclave error: {response.get('error')}")
        
        return EnclaveOutput(
            ciphertext=response['ciphertext'],
            status='success'
        )
        
    except Exception as e:
        activity.logger.error(f"Enclave activity failed: {e}")
        raise


@activity.defn
async def log_workflow_progress(message: str) -> None:
    """Activity to log workflow progress (for debugging)."""
    activity.logger.info(f"Workflow progress: {message}")
```

## Step 5: Define Workflows

```python
# host/workflows.py
from datetime import timedelta
from temporalio import workflow
from dataclasses import dataclass
from typing import Optional

with workflow.unsafe.imports_passed_through():
    from activities import (
        secure_enclave_activity,
        log_workflow_progress,
        EnclaveInput,
        EnclaveOutput
    )


@dataclass
class WorkflowInput:
    """Input for the confidential workflow."""
    initial_data: str


@dataclass
class WorkflowOutput:
    """Output from the confidential workflow."""
    final_ciphertext: str
    steps_completed: int


@workflow.defn
class ConfidentialMultiAgentWorkflow:
    """
    Workflow that coordinates confidential data processing between agents.
    
    Flow:
    1. Agent A receives initial input, encrypts state
    2. Agent B receives encrypted state, decrypts, processes, re-encrypts
    """
    
    @workflow.run
    async def run(self, input: WorkflowInput) -> WorkflowOutput:
        workflow.logger.info("Starting confidential multi-agent workflow")
        
        # Step 1: Agent A generates and encrypts initial state
        await workflow.execute_activity(
            log_workflow_progress,
            "Starting Agent A processing",
            start_to_close_timeout=timedelta(seconds=10)
        )
        
        agent_a_result = await workflow.execute_activity(
            secure_enclave_activity,
            EnclaveInput(mode='A', payload=input.initial_data),
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=workflow.RetryPolicy(
                maximum_attempts=3,
                backoff_coefficient=2.0,
            )
        )
        
        workflow.logger.info(f"Agent A completed. Ciphertext length: {len(agent_a_result.ciphertext)}")
        
        # Step 2: Agent B decrypts, processes, and re-encrypts
        await workflow.execute_activity(
            log_workflow_progress,
            "Starting Agent B processing",
            start_to_close_timeout=timedelta(seconds=10)
        )
        
        agent_b_result = await workflow.execute_activity(
            secure_enclave_activity,
            EnclaveInput(mode='B', payload=agent_a_result.ciphertext),
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=workflow.RetryPolicy(
                maximum_attempts=3,
                backoff_coefficient=2.0,
            )
        )
        
        workflow.logger.info(f"Agent B completed. Final ciphertext length: {len(agent_b_result.ciphertext)}")
        
        await workflow.execute_activity(
            log_workflow_progress,
            "Workflow completed successfully",
            start_to_close_timeout=timedelta(seconds=10)
        )
        
        return WorkflowOutput(
            final_ciphertext=agent_b_result.ciphertext,
            steps_completed=2
        )
```

## Step 6: Create Worker Entry Point

```python
# host/worker.py
import asyncio
import logging
from temporalio.client import Client, TLSConfig
from temporalio.worker import Worker

from config import (
    TEMPORAL_HOST,
    TEMPORAL_NAMESPACE,
    TEMPORAL_TASK_QUEUE,
    TEMPORAL_TLS_ENABLED,
    TEMPORAL_TLS_CERT_PATH,
    TEMPORAL_TLS_KEY_PATH,
)
from activities import secure_enclave_activity, log_workflow_progress
from workflows import ConfidentialMultiAgentWorkflow

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def get_temporal_client() -> Client:
    """Create a Temporal client with appropriate configuration."""
    
    tls_config = None
    if TEMPORAL_TLS_ENABLED:
        with open(TEMPORAL_TLS_CERT_PATH, 'rb') as f:
            client_cert = f.read()
        with open(TEMPORAL_TLS_KEY_PATH, 'rb') as f:
            client_key = f.read()
        
        tls_config = TLSConfig(
            client_cert=client_cert,
            client_private_key=client_key,
        )
    
    return await Client.connect(
        TEMPORAL_HOST,
        namespace=TEMPORAL_NAMESPACE,
        tls=tls_config,
    )


async def main():
    """Main entry point for the worker."""
    logger.info("Starting Temporal worker...")
    logger.info(f"Connecting to {TEMPORAL_HOST}/{TEMPORAL_NAMESPACE}")
    
    client = await get_temporal_client()
    
    worker = Worker(
        client,
        task_queue=TEMPORAL_TASK_QUEUE,
        workflows=[ConfidentialMultiAgentWorkflow],
        activities=[secure_enclave_activity, log_workflow_progress],
    )
    
    logger.info(f"Worker listening on task queue: {TEMPORAL_TASK_QUEUE}")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
```

## Step 7: Create Workflow Starter (for testing)

```python
# host/start_workflow.py
import asyncio
import uuid
from temporalio.client import Client

from config import TEMPORAL_HOST, TEMPORAL_NAMESPACE, TEMPORAL_TASK_QUEUE
from workflows import ConfidentialMultiAgentWorkflow, WorkflowInput


async def main():
    """Start a workflow for testing."""
    client = await Client.connect(
        TEMPORAL_HOST,
        namespace=TEMPORAL_NAMESPACE,
    )
    
    workflow_id = f"confidential-workflow-{uuid.uuid4().hex[:8]}"
    
    print(f"Starting workflow: {workflow_id}")
    
    result = await client.execute_workflow(
        ConfidentialMultiAgentWorkflow.run,
        WorkflowInput(initial_data="Hello from the host!"),
        id=workflow_id,
        task_queue=TEMPORAL_TASK_QUEUE,
    )
    
    print(f"Workflow completed!")
    print(f"Final ciphertext: {result.final_ciphertext[:50]}...")
    print(f"Steps completed: {result.steps_completed}")


if __name__ == "__main__":
    asyncio.run(main())
```

## Step 8: Run the Worker

```bash
# Activate virtual environment
source venv/bin/activate

# Start the worker
python worker.py

# In another terminal, start a workflow
python start_workflow.py
```

## Verification

1. **Check Temporal Web UI**
   - Open http://localhost:8080 (self-hosted) or Temporal Cloud UI
   - Navigate to your namespace
   - Find the workflow execution
   - Inspect Input/Output - should show encrypted ciphertext, not plaintext

2. **Check Worker Logs**
   - Worker should log activity executions
   - No plaintext data should appear in logs

## Troubleshooting

### Issue: `Connection refused` to Temporal

**Cause**: Temporal server not running or wrong address

**Solution**: Verify Temporal is running and `TEMPORAL_HOST` is correct

### Issue: `vsock connection failed`

**Cause**: Enclave not running or wrong CID

**Solution**:
```bash
# Get enclave CID
nitro-cli describe-enclaves
# Update ENCLAVE_CID in config
```

### Issue: `Activity timeout`

**Cause**: Enclave processing taking too long

**Solution**: Increase `start_to_close_timeout` in workflow definition

## Next Steps

After completing all setup:
1. Build and run the enclave (see [04-enclave-development.md](./04-enclave-development.md))
2. Start the host worker
3. Execute a test workflow
4. Verify encrypted data in Temporal UI (see README Verification Procedure)
