"""Adapter connecting native cognition to PIKA's existing PIKABrain router."""
from __future__ import annotations

from typing import Any

from agents.base import Agent
from core.native_cognition import NativeCognitionEngine


class NativeCognitionAgent(Agent):
    name = "native"
    capabilities = [
        "coding", "reasoning", "generation", "analysis", "planning", "debugging",
    ]

    def __init__(self, root: str | None = None) -> None:
        self.engine = NativeCognitionEngine(root)

    async def execute(self, task: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self.engine.execute(task, context)
