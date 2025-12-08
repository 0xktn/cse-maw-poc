"""
Temporal Workflows

Workflow definitions for confidential processing.
"""

from datetime import timedelta
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from activities import process_in_enclave


@workflow.defn
class ConfidentialWorkflow:
    """
    Workflow that orchestrates confidential processing in the enclave.
    """
    
    @workflow.run
    async def run(self, input_data: str) -> str:
        """Execute the confidential workflow."""
        result = await workflow.execute_activity(
            process_in_enclave,
            input_data,
            start_to_close_timeout=timedelta(minutes=5),
        )
        return result
