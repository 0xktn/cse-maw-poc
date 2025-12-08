"""
Temporal Worker Entry Point

Connects to Temporal server and waits for workflow tasks.
"""

import asyncio
import os
import logging

from temporalio.client import Client
from temporalio.worker import Worker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
TEMPORAL_HOST = os.environ.get("TEMPORAL_HOST", "localhost:7233")
TEMPORAL_NAMESPACE = os.environ.get("TEMPORAL_NAMESPACE", "confidential-workflow-poc")
TASK_QUEUE = os.environ.get("TASK_QUEUE", "confidential-workflow-tasks")


async def main():
    """Main worker entry point."""
    logger.info(f"Connecting to Temporal at {TEMPORAL_HOST}")
    
    client = await Client.connect(TEMPORAL_HOST, namespace=TEMPORAL_NAMESPACE)
    logger.info(f"Connected to namespace: {TEMPORAL_NAMESPACE}")
    
    # Import activities and workflows
    from activities import process_in_enclave
    from workflows import ConfidentialWorkflow
    
    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[ConfidentialWorkflow],
        activities=[process_in_enclave],
    )
    
    logger.info(f"Starting worker on queue: {TASK_QUEUE}")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
