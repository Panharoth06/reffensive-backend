import json
from typing import AsyncGenerator

import redis.asyncio as redis


class ProgressSubscriber:
    """
    Redis Pub/Sub subscriber for scan progress events.
    
    Subscribes to channel: sonarqube:scan:progress:{scan_id}
    Yields progress events until terminal status is reached.
    """

    CHANNEL_PREFIX = "sonarqube:scan:progress"

    def __init__(self, redis_url: str):
        """Initialize with Redis URL."""
        self.redis_url = redis_url
        self.redis: redis.Redis | None = None
        self.pubsub: redis.client.PubSub | None = None

    async def subscribe(self, scan_id: str) -> AsyncGenerator[dict, None]:
        """
        Subscribe to progress events for a scan.
        
        Args:
            scan_id: The scan ID to subscribe to
            
        Yields:
            Progress event dictionaries
        """
        self.redis = redis.from_url(self.redis_url)
        self.pubsub = self.redis.pubsub()
        channel = f"{self.CHANNEL_PREFIX}:{scan_id}"

        await self.pubsub.subscribe(channel)
        try:
            async for message in self.pubsub.listen():
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        yield data
                        # Stop on terminal status
                        if data.get("status") in ["SUCCESS", "FAILED", "PARTIAL"]:
                            break
                    except json.JSONDecodeError:
                        continue
        finally:
            await self.pubsub.unsubscribe(channel)
            await self.pubsub.close()

    async def close(self) -> None:
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()
