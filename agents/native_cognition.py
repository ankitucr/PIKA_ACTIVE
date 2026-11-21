"""Adapter connecting native cognition to PIKA's existing PIKABrain router."""
from __future__ import annotations

from typing import Any

from agents.base import Agent
from core.native_cognition import NativeCognitionEngine


class NativeCognitionAgent(Agent):
    name = "native"
    # Advertise only operations with implemented, deterministic handlers.
    # Generic coding/reasoning/generation claims caused capability-aware routing
    # to select this agent for tasks it must explicitly reject.
    capabilities = [
        "python_static_analysis",
        "python_syntax_validation",
        "python_snippet_comparison",
        "github_repository_learning",
        "pika_self_ast_analysis",
        "static_improvement_queue",
        "lexical_code_evidence_retrieval",
        "engineering_knowledge_retrieval",
    ]

    def __init__(self, root: str | None = None) -> None:
        self.engine = NativeCognitionEngine(root)

    async def execute(self, task: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self.engine.execute(task, context)
