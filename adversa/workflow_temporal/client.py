from __future__ import annotations

from datetime import timedelta

from temporalio.client import Client

from adversa.constants import DEFAULT_NAMESPACE, TASK_QUEUE
from adversa.workflow_temporal.workflows import AdversaRunWorkflow


async def get_client(address: str = "localhost:7233", namespace: str = DEFAULT_NAMESPACE) -> Client:
    return await Client.connect(address, namespace=namespace)


async def start_run(client: Client, workflow_id: str, payload: dict, task_queue: str = TASK_QUEUE) -> str:
    handle = await client.start_workflow(
        AdversaRunWorkflow.run,
        payload,
        id=workflow_id,
        task_queue=task_queue,
        execution_timeout=timedelta(hours=24),
    )
    return handle.id


async def signal_pause(client: Client, workflow_id: str) -> None:
    await client.get_workflow_handle(workflow_id).signal(AdversaRunWorkflow.pause)


async def signal_resume(client: Client, workflow_id: str) -> None:
    await client.get_workflow_handle(workflow_id).signal(AdversaRunWorkflow.resume)


async def signal_update_config(client: Client, workflow_id: str) -> None:
    await client.get_workflow_handle(workflow_id).signal(AdversaRunWorkflow.update_config)


async def signal_cancel(client: Client, workflow_id: str) -> None:
    await client.get_workflow_handle(workflow_id).signal(AdversaRunWorkflow.cancel)


async def query_status(client: Client, workflow_id: str) -> dict:
    return await client.get_workflow_handle(workflow_id).query(AdversaRunWorkflow.status)
