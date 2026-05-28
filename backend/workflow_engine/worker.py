"""
Temporal Worker for Distributed Scaling.

Runs workflows and activities to enable horizontal scaling.
"""
import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from .activities import analyze_repository, create_pr, generate_patch, validate_patch
from .temporal_workflow import SentinelRemediationWorkflow


async def main():
    # Connect client to Temporal server
    client = await Client.connect("localhost:7233")

    # Run the worker
    worker = Worker(
        client,
        task_queue="sentinel-task-queue",
        workflows=[SentinelRemediationWorkflow],
        activities=[analyze_repository, generate_patch, validate_patch, create_pr],
    )
    print("Temporal Worker started. Listening on 'sentinel-task-queue'...")
    await worker.run()

if __name__ == "__main__":
    asyncio.run(main())
