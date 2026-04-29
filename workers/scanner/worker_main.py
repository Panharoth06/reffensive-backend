"""
Scanner worker main loop.
Polls go-server for queued scan jobs and processes them.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

import grpc

sys.path.insert(0, str(Path(__file__).parent))
from proto import tool_pb2, tool_pb2_grpc
from scanner import process

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

GO_SERVER_ADDR = os.getenv("GO_SERVER_ADDR", "go-server:50051")
POLL_INTERVAL  = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))


def main():
    log.info("Scanner worker starting, connecting to %s", GO_SERVER_ADDR)
    channel = grpc.insecure_channel(GO_SERVER_ADDR)
    stub    = tool_pb2_grpc.ToolServiceStub(channel)

    while True:
        try:
            resp = stub.ListQueuedScanJobs(
                tool_pb2.ListQueuedScanJobsRequest(limit=10)
            )
            for job in resp.jobs:
                log.info("Processing scan job %s → %s", job.id, job.target)
                task = {
                    "tool_id":     job.tool_id,
                    "scan_job_id": job.id,
                    "image_ref":   job.image_ref,
                    "target":      job.target,
                    "params_json": json.loads(job.params_jsonb or "{}"),
                }
                process(task)

        except grpc.RpcError as e:
            log.warning("gRPC error: %s — retrying in %ds", e.details(), POLL_INTERVAL)
        except Exception as e:
            log.exception("Unexpected error: %s", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()