"""
Builder worker main loop.
Polls go-server for queued build jobs and processes them.
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
try:
    import create_tool_pb2 as tool_pb2
    import create_tool_pb2_grpc as tool_pb2_grpc
except ModuleNotFoundError:
    from proto import create_tool_pb2 as tool_pb2
    from proto import create_tool_pb2_grpc as tool_pb2_grpc
from builder import BuildTask, process

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

GO_SERVER_ADDR = os.getenv("GO_SERVER_ADDR", "go-server:50051")
POLL_INTERVAL  = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))


def main():
    log.info("Builder worker starting, connecting to %s", GO_SERVER_ADDR)
    channel = grpc.insecure_channel(GO_SERVER_ADDR)
    stub    = tool_pb2_grpc.ToolServiceStub(channel)

    while True:
        try:
            resp = stub.ListQueuedBuildJobs(
                tool_pb2.ListQueuedBuildJobsRequest(limit=10)
            )
            for job in resp.jobs:
                log.info("Processing build job %s for tool %s", job.id, job.tool_id)
                task = BuildTask(
                    tool_id        = job.tool_id,
                    build_job_id   = job.id,
                    install_method = job.install_method,
                    image_source   = job.image_source,
                    build_json     = json.loads(job.build_jsonb or "{}"),
                )
                process(task)

        except grpc.RpcError as e:
            log.warning("gRPC error: %s — retrying in %ds", e.details(), POLL_INTERVAL)
        except Exception as e:
            log.exception("Unexpected error: %s", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
