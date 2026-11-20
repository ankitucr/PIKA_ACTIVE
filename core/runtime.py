from pathlib import Path

from core.router import AgentRouter
from core.tool_runtime import ToolRuntime

from agents.native_cognition import NativeCognitionAgent

from skills.registry import SkillRegistry
from skills.builtin import register_builtin_skills

from tools.registry import ToolRegistry
from tools.builtin import register_builtin_tools


def create_runtime(root: str | None = None) -> AgentRouter:

    router = AgentRouter()

    native_agent = NativeCognitionAgent(root=root)

    router.register(
        native_agent
    )

    return router


def create_tool_runtime(workspace_root: str | Path | None = None) -> ToolRuntime:

    skills = SkillRegistry()
    tools = ToolRegistry()

    register_builtin_skills(
        skills
    )

    register_builtin_tools(
        tools,
        workspace_root=(workspace_root or Path(__file__).resolve().parents[1] / "workspace"),
    )

    return ToolRuntime(
        skills=skills,
        tools=tools,
    )
