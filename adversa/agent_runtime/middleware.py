from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.parse import urljoin

from langchain.agents.middleware import AgentMiddleware
from langchain.agents.middleware.types import ModelRequest, ModelResponse
from langchain_core.messages import SystemMessage, ToolMessage
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.config.load import load_config
from adversa.logging.audit import AuditLogger
from adversa.security.rule_compiler import CompiledRule, compile_rules
from adversa.security.rules import RuntimeTarget, evaluate_runtime_boundary


@dataclass(frozen=True)
class NormalizedToolBoundary:
    tool: str
    host: str
    subdomain: str
    path: str
    repo_path: str
    method: str | None
    url: str


class RulesGuardrailMiddleware(AgentMiddleware):
    def __init__(
        self,
        context: AdversaAgentContext,
        compiled_rules: list[CompiledRule] | None = None,
        allowed_repo_virtual_prefix: str | None = None,
    ):
        self._context = context
        self._compiled_rules = compiled_rules or compile_rules(load_config(context.config_path))
        self._audit = AuditLogger(context.logs_dir)
        self._allowed_repo_virtual_prefix = allowed_repo_virtual_prefix
        context.evidence_dir.mkdir(parents=True, exist_ok=True)

    def wrap_model_call(
        self,
        request: ModelRequest,
        handler: Callable[[ModelRequest], ModelResponse],
    ) -> ModelResponse:
        prompt = self._policy_prompt()
        system_message = request.system_message
        if system_message is not None and system_message.text == prompt:
            return handler(request)
        return handler(request.override(system_message=SystemMessage(content=prompt)))

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        filesystem_violation = self._check_filesystem_boundary(request)
        if filesystem_violation:
            return self._blocked_tool_message(request, filesystem_violation)
        boundary = self._normalize_tool_call(request)
        target = RuntimeTarget.from_inputs(
            phase=self._context.phase,
            url=boundary.url,
            repo_path=boundary.repo_path,
            method=boundary.method,
        )
        decision = evaluate_runtime_boundary(target, self._compiled_rules)
        if decision.blocked_reason:
            self._record_denial(request, boundary, target, decision.blocked_reason, decision.applied_rules)
            return self._blocked_tool_message(request, decision.blocked_reason)
        return handler(request)

    def _policy_prompt(self) -> str:
        lines = [
            "Adversa policy guardrails are active.",
            f"Phase: {self._context.phase}",
            f"Base URL: {self._context.url}",
            f"Repo path: {self._context.repo_path}",
            "Rules:",
        ]
        if not self._compiled_rules:
            lines.append("- No explicit focus/avoid rules configured.")
        else:
            for rule in self._compiled_rules:
                scope = f" phases={list(rule.phases)}" if rule.phases else ""
                description = f" ({rule.description})" if rule.description else ""
                lines.append(f"- {rule.action} {rule.target_type}={rule.target}{scope}{description}")
        lines.append("Never plan or execute tool calls that cross an avoid boundary.")
        return "\n".join(lines)

    def _normalize_tool_call(self, request: ToolCallRequest) -> NormalizedToolBoundary:
        args = request.tool_call.get("args", {}) or {}
        path = str(args.get("path") or args.get("url_path") or args.get("endpoint") or "/")
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = urljoin(self._context.url.rstrip("/") + "/", path.lstrip("/"))
        repo_path = str(args.get("repo_path") or args.get("pathspec") or self._context.repo_path)
        method = args.get("method")
        target = RuntimeTarget.from_inputs(
            phase=self._context.phase,
            url=url,
            repo_path=repo_path,
            method=str(method) if method is not None else None,
        )
        return NormalizedToolBoundary(
            tool=request.tool_call["name"],
            host=target.host,
            subdomain=target.subdomain,
            path=target.path,
            repo_path=target.repo_path,
            method=target.method,
            url=url,
        )

    def _check_filesystem_boundary(self, request: ToolCallRequest) -> str | None:
        if not self._allowed_repo_virtual_prefix:
            return None

        tool_name = request.tool_call["name"]
        args = request.tool_call.get("args", {}) or {}
        candidate_paths = [
            args.get("file_path"),
            args.get("path"),
            args.get("target_file"),
        ]
        if tool_name == "glob":
            candidate_paths.append(args.get("pattern"))
        if tool_name == "grep":
            candidate_paths.append(args.get("glob"))

        for candidate in candidate_paths:
            if candidate is None:
                continue
            if not self._is_allowed_repo_virtual_path(str(candidate)):
                return (
                    f"Tool '{tool_name}' path '{candidate}' is outside the authorized repo prefix "
                    f"'{self._allowed_repo_virtual_prefix}'."
                )
        return None

    def _is_allowed_repo_virtual_path(self, candidate: str) -> bool:
        if not candidate:
            return True
        normalized_candidate = candidate
        if candidate.startswith("**") or candidate.startswith("*"):
            return False
        if not candidate.startswith("/"):
            normalized_candidate = "/" + candidate
        normalized = PurePosixPath(normalized_candidate)
        prefix = PurePosixPath(self._allowed_repo_virtual_prefix)
        if str(normalized).startswith(str(prefix)):
            return True
        if any(token in candidate for token in ("*", "?")):
            anchor = normalized.parts[1] if len(normalized.parts) > 1 else ""
            return str(prefix).startswith(f"/{anchor}") and str(normalized).startswith(str(prefix))
        return False

    def _blocked_tool_message(self, request: ToolCallRequest, reason: str) -> ToolMessage:
        return ToolMessage(
            content=f"Tool call blocked by policy: {reason}",
            tool_call_id=request.tool_call["id"],
            status="error",
            name=request.tool_call["name"],
        )

    def _record_denial(
        self,
        request: ToolCallRequest,
        boundary: NormalizedToolBoundary,
        target: RuntimeTarget,
        reason: str,
        applied_rules: list[Any],
    ) -> None:
        payload = {
            "event_type": "agent_tool_call_blocked",
            "workspace": self._context.workspace,
            "run_id": self._context.run_id,
            "phase": self._context.phase,
            "tool": boundary.tool,
            "tool_call": request.tool_call,
            "boundary": boundary.__dict__,
            "runtime_target": target.__dict__,
            "reason": reason,
            "applied_rules": [rule.__dict__ for rule in applied_rules],
        }
        self._audit.log_tool_call(payload)
        evidence_path = self._context.evidence_dir / f"agent-guardrail-{request.tool_call['id']}.json"
        evidence_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_rules_middleware(context: AdversaAgentContext) -> RulesGuardrailMiddleware:
    return RulesGuardrailMiddleware(context=context)


def load_runtime_boundary_middleware(
    context: AdversaAgentContext,
    *,
    allowed_repo_virtual_prefix: str,
) -> RulesGuardrailMiddleware:
    return RulesGuardrailMiddleware(
        context=context,
        allowed_repo_virtual_prefix=allowed_repo_virtual_prefix,
    )
