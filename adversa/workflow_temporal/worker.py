from __future__ import annotations

import asyncio

from temporalio.worker import Worker

from adversa.constants import TASK_QUEUE
from adversa.workflow_temporal.activities import (
    provider_health_check,
    run_intake_activity,
    run_netdisc_activity,
    run_phase_activity,  # kept for in-flight workflow backwards compat
    run_prerecon_activity,
    run_recon_activity,
    run_report_activity,
    run_vuln_activity,
)
from adversa.workflow_temporal.client import get_client
from adversa.workflow_temporal.workflows import AdversaRunWorkflow


def build_worker(client) -> Worker:  # type: ignore[no-untyped-def]
    return Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[AdversaRunWorkflow],
        activities=[
            provider_health_check,
            run_intake_activity,
            run_prerecon_activity,
            run_netdisc_activity,
            run_recon_activity,
            run_vuln_activity,
            run_report_activity,
            run_phase_activity,  # backwards compat for in-flight workflows
        ],
    )


async def run_worker() -> None:
    client = await get_client()
    worker = build_worker(client)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run_worker())
