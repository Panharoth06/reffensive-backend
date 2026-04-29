"""
Scanner worker runs as a separate process/container.

Receives ScanTask messages from the queue, runs the tool's Docker image
against the target, captures output, and writes results back via gRPC.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys

import grpc

sys.path.insert(0, os.path.dirname(__file__))
from proto import tool_pb2, tool_pb2_grpc

log = logging.getLogger(__name__)

GO_SERVER_ADDR = os.getenv("GO_SERVER_ADDR", "localhost:50051")
SCAN_TIMEOUT   = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))


def process(task: dict) -> None:
    """
    Entry point called by the queue consumer.
    task keys: tool_id, scan_job_id, image_ref, target, params_json (dict)
    """
    channel = grpc.insecure_channel(GO_SERVER_ADDR)
    stub    = tool_pb2_grpc.ToolServiceStub(channel)

    job_id    = task["scan_job_id"]
    image_ref = task["image_ref"]
    target    = task["target"]
    params    = task.get("params_json") or {}

    # Mark running
    stub.StartScanJob(tool_pb2.StartScanJobRequest(id=job_id))

    try:
        raw_output = _run_scan(image_ref, target, params)
        stub.FinishScanJob(tool_pb2.FinishScanJobRequest(
            id=job_id,
            status=tool_pb2.SUCCEEDED,
            raw_output=raw_output,
            error="",
        ))
        log.info("Scan %s completed successfully", job_id)

    except Exception as exc:
        log.exception("Scan %s failed", job_id)
        stub.FinishScanJob(tool_pb2.FinishScanJobRequest(
            id=job_id,
            status=tool_pb2.JOB_FAILED,
            raw_output="",
            error=str(exc),
        ))
    finally:
        channel.close()


def _run_scan(image_ref: str, target: str, params: dict) -> str:
    """
    Runs the tool image via Docker with the target and params.
    Params are passed as environment variables (ENV_*) by convention.
    Tools must write results to stdout.
    """
    env_args: list[str] = []
    for k, v in params.items():
        env_args += ["-e", f"SCAN_{k.upper()}={v}"]

    if params.get("net_raw") or params.get("privileged") or params.get("device"):
        raise RuntimeError("requested runtime capabilities violate platform policy")

    cmd = [
        "docker", "run", "--rm",
        "--runtime", "runsc",
        "--network", "bridge",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        *env_args,
        image_ref,
        target,
    ]

    log.info("Running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Scanner exited {result.returncode}: {result.stderr[:2000]}"
        )

    return result.stdout
