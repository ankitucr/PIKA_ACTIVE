from typing import Any
import builtins


class AgentRouter:

    def __init__(self):
        self.agents: dict[str, Any] = {}

    def register(
        self,
        agent: Any,
    ) -> None:

        self.agents[agent.name] = agent

    def get(
        self,
        name: str,
    ) -> Any:

        if name not in self.agents:
            raise ValueError(
                f"Agent '{name}' is not registered."
            )

        return self.agents[name]

    def select(
        self,
        preferred: str | None = None,
        required_capabilities: builtins.list[str] | None = None,
    ) -> Any:

        # ---------------------------------------------------------
        # Explicit agent preference
        # ---------------------------------------------------------

        if preferred:
            if preferred not in self.agents:
                raise ValueError(
                    f"Agent '{preferred}' is not registered."
                )

            return self.agents[preferred]

        # ---------------------------------------------------------
        # Capability-aware selection
        # ---------------------------------------------------------

        required_capabilities = (
            required_capabilities or []
        )

        if required_capabilities:

            best_agent = None
            best_score = -1

            for agent in self.agents.values():

                agent_capabilities = set(
                    getattr(
                        agent,
                        "capabilities",
                        [],
                    )
                )

                score = len(
                    agent_capabilities.intersection(
                        required_capabilities
                    )
                )
                # Some narrow native handlers expose intent-specific routing
                # markers separately from their public general capabilities.
                native_reasoning_capabilities = set(
                    getattr(agent, "native_reasoning_capabilities", ())
                )
                score += len(
                    native_reasoning_capabilities.intersection(
                        required_capabilities
                    )
                )

                if score > best_score:
                    best_score = score
                    best_agent = agent

            if best_agent is not None and best_score > 0:
                return best_agent

            # A native-only capability must never fall through to the
            # generic API worker when its implementation is unavailable.
            if {"native_fact_reasoning", "native_self_evolution", "native_symbolic_reasoning"}.intersection(required_capabilities):
                return None

        # ---------------------------------------------------------
        # Current default worker
        # ---------------------------------------------------------

        if "api" in self.agents:
            return self.agents["api"]

        if not self.agents:
            raise RuntimeError(
                "No agents registered."
            )

        return next(
            iter(self.agents.values())
        )

    def list(self) -> builtins.list[str]:
        return list(
            self.agents.keys()
        )

    def capabilities(self) -> dict[str, builtins.list[str]]:

        return {
            name: list(
                getattr(
                    agent,
                    "capabilities",
                    [],
                )
            )
            for name, agent in self.agents.items()
        }
