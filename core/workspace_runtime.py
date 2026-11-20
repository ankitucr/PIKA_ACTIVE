from pathlib import Path
from typing import Any

from tools.registry import Tool, ToolRegistry
from tools.workspace import WorkspaceTools


class WorkspaceRuntime:
    """Root-scoped workspace tool registry; command execution fails closed."""

    def __init__(self, workspace_root: str | Path):
        self.workspace = WorkspaceTools(workspace_root)
        self.tools = ToolRegistry()
        self._register_tools()

    def _register_tools(self) -> None:
        definitions = [
            ("workspace_list", "List project files.", ["workspace", "inspection"], self.workspace.list_files),
            ("workspace_read", "Read a project text file.", ["workspace", "inspection", "code_analysis"], self.workspace.read_file),
            ("workspace_search", "Search project source code.", ["workspace", "inspection", "code_analysis", "debugging"], self.workspace.search),
            ("workspace_write", "Write a file inside the configured workspace only.", ["workspace", "workspace_write"], self.workspace.write_file),
            ("workspace_validate_python", "Validate Python syntax without executing source.", ["workspace", "validation", "debugging"], self.workspace.validate_python),
            ("workspace_check_python", "Compatibility alias for syntax-only Python validation.", ["workspace", "validation", "debugging"], self.workspace.check_python),
            ("workspace_run_python_test", "Run a test only when an audited OS sandbox exists; currently fail-closed.", ["workspace", "validation", "debugging"], self.workspace.run_python_test),
            ("workspace_run", "Command execution is disabled until an audited OS sandbox is integrated.", ["workspace", "execution"], self.workspace.run_command),
        ]
        for name, description, capabilities, handler in definitions:
            self.tools.register(Tool(name=name, description=description,
                                     capabilities=capabilities, handler=handler))

    def discover(self, capabilities: list[str]) -> dict[str, Any]:
        selected = self.tools.select(capabilities)
        return {"capabilities": capabilities, "tools": [tool.name for tool in selected]}

    def execute(self, tool_name: str, **kwargs: Any) -> Any:
        return self.tools.execute(tool_name, **kwargs)
