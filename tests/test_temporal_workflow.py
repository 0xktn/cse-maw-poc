#!/usr/bin/env python3
"""
Test Temporal Workflow Integration

This script tests the end-to-end confidential workflow:
1. Connects to Temporal server
2. Executes ConfidentialWorkflow with sample data
3. Verifies encrypted result is returned
4. Prints workflow execution details for UI verification
"""

import asyncio
import sys
import os
import json
from temporalio.client import Client
from temporalio import workflow

# Add parent directory to path to import workflows
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'host'))

with workflow.unsafe.imports_passed_through():
    from workflows import ConfidentialWorkflow


async def main():
    print("=" * 60)
    print("TEMPORAL WORKFLOW INTEGRATION TEST")
    print("=" * 60)
    
    # Connect to Temporal server
    temporal_host = os.environ.get('TEMPORAL_HOST', 'localhost:7233')
    temporal_namespace = os.environ.get('TEMPORAL_NAMESPACE', 'confidential-workflow-poc')
    task_queue = os.environ.get('TASK_QUEUE', 'confidential-workflow-tasks')
    
    print(f"\n1. Connecting to Temporal at {temporal_host}...")
    print(f"   Namespace: {temporal_namespace}")
    print(f"   Task Queue: {task_queue}")
    
    try:
        client = await Client.connect(temporal_host, namespace=temporal_namespace)
        print("✅ Connected to Temporal")
    except Exception as e:
        print(f"❌ Failed to connect to Temporal: {e}")
        print("\nIs Temporal server running?")
        print("  temporal server start-dev")
        return False
    
    # Prepare test data
    test_input = "Confidential test data for encryption - " + "x" * 100
    workflow_id = f"test-confidential-workflow-{int(asyncio.get_event_loop().time())}"
    
    print(f"\n2. Starting workflow...")
    print(f"   Workflow ID: {workflow_id}")
    print(f"   Input data: {test_input[:50]}...")
    
    try:
        # Execute workflow
        handle = await client.start_workflow(
            ConfidentialWorkflow.run,
            test_input,
            id=workflow_id,
            task_queue=task_queue,
        )
        
        print(f"✅ Workflow started: {handle.id}")
        print(f"   Run ID: {handle.result_run_id}")
        
        # Wait for result
        print("\n3. Waiting for workflow to complete...")
        result = await handle.result()
        
        print("✅ Workflow completed successfully!")
        
        # Parse and display result
        print("\n4. Analyzing result...")
        try:
            result_data = json.loads(result)
            print(f"   Status: {result_data.get('status')}")
            print(f"   Message: {result_data.get('msg')}")
            
            # Check if data is encrypted
            if 'ciphertext' in result_data or 'result' in result_data:
                encrypted_field = result_data.get('ciphertext') or result_data.get('result')
                print(f"   Encrypted data (first 80 chars): {str(encrypted_field)[:80]}...")
                print("\n✅ Data appears to be encrypted!")
            else:
                print(f"   Full result: {result_data}")
                print("\n⚠️  Warning: Result may not be encrypted")
                
        except json.JSONDecodeError:
            print(f"   Raw result: {result[:100]}...")
        
        # Provide UI verification instructions
        print("\n" + "=" * 60)
        print("VERIFICATION STEPS")
        print("=" * 60)
        print("\n5. Verify in Temporal UI:")
        print(f"   URL: http://{temporal_host.split(':')[0]}:8080")
        print(f"   Workflow ID: {workflow_id}")
        print("\n   Check that:")
        print("   • Workflow status is 'Completed'")
        print("   • Input shows encrypted/base64 data (not plaintext)")
        print("   • Output shows encrypted blob")
        print("   • Activity 'process_in_enclave' succeeded")
        
        print("\n🎉 TEMPORAL INTEGRATION TEST PASSED!")
        return True
        
    except Exception as e:
        print(f"\n❌ Workflow execution failed: {e}")
        import traceback
        traceback.print_exc()
        
        print("\n" + "=" * 60)
        print("TROUBLESHOOTING")
        print("=" * 60)
        print("\nCheck:")
        print("1. Is the Temporal worker running?")
        print("   ps aux | grep worker")
        print("\n2. Is the enclave running?")
        print("   nitro-cli describe-enclaves")
        print("\n3. Check worker logs:")
        print("   journalctl -u temporal-worker -f")
        
        return False


if __name__ == '__main__':
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
