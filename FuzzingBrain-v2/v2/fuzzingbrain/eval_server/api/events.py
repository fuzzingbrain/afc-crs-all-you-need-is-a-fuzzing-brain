"""Events API routes."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class EventData(BaseModel):
    """Single event data."""
    event_id: str
    event_type: str
    timestamp: str
    severity: str = "info"
    instance_id: str = ""
    task_id: str = ""
    worker_id: str = ""
    agent_id: str = ""
    agent_type: str = ""
    operation: str = ""
    payload: Dict[str, Any] = {}
    tags: List[str] = []


class EventsBatch(BaseModel):
    """Batch of events."""
    events: List[EventData]


@router.post("")
async def receive_events(batch: EventsBatch) -> Dict[str, Any]:
    """Receive batch of events from FuzzingBrain instance."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, redis_store = storage

    # Convert to MongoDB format
    events = []
    for event in batch.events:
        events.append({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")),
            "severity": event.severity,
            "instance_id": event.instance_id,
            "task_id": event.task_id,
            "worker_id": event.worker_id,
            "agent_id": event.agent_id,
            "agent_type": event.agent_type,
            "operation": event.operation,
            "payload": event.payload,
            "tags": event.tags,
        })

    # Store in MongoDB
    await mongo.insert_events(events)

    # Publish to Redis for real-time subscribers
    if redis_store:
        for event in batch.events:
            await redis_store.publish_event(
                f"events:{event.event_type}",
                event.model_dump(),
            )
            if event.task_id:
                await redis_store.publish_event(
                    f"events:task:{event.task_id}",
                    event.model_dump(),
                )

    return {"success": True, "count": len(batch.events)}


@router.get("")
async def list_events(
    task_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List events with filters."""
    from ..server import get_storage

    storage = get_storage()
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")

    mongo, _ = storage
    events = await mongo.get_events(
        task_id=task_id,
        event_type=event_type,
        limit=limit,
    )

    # Convert datetime to string
    for event in events:
        if isinstance(event.get("timestamp"), datetime):
            event["timestamp"] = event["timestamp"].isoformat()
        event.pop("_id", None)

    return events
