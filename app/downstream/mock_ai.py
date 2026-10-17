"""In-process mock downstream receiver used by the gateway demo."""
from __future__ import annotations

from fastapi import APIRouter


class MockDownstream:
    def receive(self, payload: dict, *, request_id: str, via: str) -> dict:
        return {"status": "accepted", "request_id": request_id, "via": via}


def create_router(_: MockDownstream) -> APIRouter:
    router = APIRouter()

    @router.post("/downstream/risk-score")
    async def risk_score() -> dict:
        return {"risk_score": 0.0, "simulated": True}

    return router