"""Agent loop over MCP tools, provider-agnostic, with hard limits and a full transcript.

Limits enforced here (not left to the model): max turns, max tool calls, per-call timeout, result-size
cap, tool allow-list per role, and a structured final answer validated against the role's schema.
A run that hits a limit or returns an invalid answer ends as `failed` / `limit` - never as a guess.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from .definitions import AgentDef
from .providers import Pricing, Provider

SUBMIT = "submit_result"


def _inline_refs(schema: dict) -> dict:
    defs = schema.pop("$defs", {})

    def walk(n):
        if isinstance(n, dict):
            if "$ref" in n:
                return walk(dict(defs[n["$ref"].split("/")[-1]]))
            return {k: walk(v) for k, v in n.items()}
        if isinstance(n, list):
            return [walk(x) for x in n]
        return n
    return walk(schema)


class ToolHub:
    """Connects to MCP servers (in-process MCPServer objects, or remote streamable-HTTP URLs) and exposes their
    tools as `<server>__<tool>`."""

    def __init__(self, servers: dict[str, Any], bearer: str | None = None, timeout_s: float = 60):
        self.servers, self.bearer, self.timeout_s = servers, bearer, timeout_s
        self.clients: dict[str, Any] = {}
        self.tools: dict[str, tuple[str, Any]] = {}
        self._stack: AsyncExitStack | None = None

    async def __aenter__(self) -> "ToolHub":
        from mcp import Client
        self._stack = AsyncExitStack()
        for name, srv in self.servers.items():
            if isinstance(srv, str):
                import httpx2
                from mcp.client.streamable_http import streamable_http_client
                http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {self.bearer}"} if self.bearer else {},
                                          timeout=self.timeout_s)
                await self._stack.enter_async_context(http)
                transport = streamable_http_client(srv, http_client=http)
                client = await self._stack.enter_async_context(Client(transport))
            else:
                client = await self._stack.enter_async_context(Client(srv))
            self.clients[name] = client
            for t in (await client.list_tools()).tools:
                self.tools[f"{name}__{t.name}"] = (name, t)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._stack:
            await self._stack.aclose()

    def specs(self, allowed: list[str]) -> list[dict[str, Any]]:
        out = []
        for full, (_, t) in sorted(self.tools.items()):
            if any(fnmatch.fnmatch(full, pat) for pat in allowed):
                out.append({"name": full, "description": (t.description or "")[:1500], "input_schema": t.input_schema})
        return out

    async def call(self, full: str, args: dict[str, Any]) -> tuple[bool, Any]:
        server, t = self.tools[full]
        r = await asyncio.wait_for(self.clients[server].call_tool(t.name, args), timeout=self.timeout_s)
        if r.structured_content is not None:
            payload = r.structured_content
            if isinstance(payload, dict) and set(payload) == {"result"}:
                payload = payload["result"]
        else:
            payload = "\n".join(getattr(c, "text", "") for c in r.content)
        return bool(r.is_error), payload


@dataclass
class AgentResult:
    kind: str
    outcome: str                       # ok | failed | limit | budget
    output: dict[str, Any] | None = None
    error: str = ""
    turns: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    model: str = ""
    provider: str = ""
    transcript: list[dict[str, Any]] = field(default_factory=list)
    seconds: float = 0.0
    degraded: bool = False             # produced by the fallback analyst (budget exhausted / model down)


def _longest_list(node: Any, path=()) -> tuple[tuple, int]:
    best: tuple[tuple, int] = ((), 0)
    if isinstance(node, list):
        best = (path, len(node))
        for i, x in enumerate(node[:50]):
            cand = _longest_list(x, path + (i,))
            if cand[1] > best[1]:
                best = cand
    elif isinstance(node, dict):
        for k, v in node.items():
            cand = _longest_list(v, path + (k,))
            if cand[1] > best[1]:
                best = cand
    return best


def _render_result(payload: Any, limit: int) -> str:
    """Serialise a tool result within `limit` characters while keeping it VALID JSON: the longest list is
    halved until it fits, and the result says it was shortened (so the model narrows its query)."""
    if isinstance(payload, str):
        return payload if len(payload) <= limit else payload[:limit] + " [truncated - narrow the query]"
    text = json.dumps(payload, default=str, separators=(",", ":"))
    if len(text) <= limit:
        return text
    data = json.loads(text)
    for _ in range(40):
        path, n = _longest_list(data)
        if n <= 1:
            break
        node = data
        for p in path[:-1]:
            node = node[p]
        node[path[-1]] = node[path[-1]][: n // 2] if path else node
        if isinstance(data, dict):
            data["_shortened"] = "result was too large and lists were cut - narrow the query for complete results"
        text = json.dumps(data, default=str, separators=(",", ":"))
        if len(text) <= limit:
            return text
    return json.dumps({"_shortened": "result too large even after cutting lists - narrow the query",
                       "preview": text[: limit // 2]})


async def run_agent(defn: AgentDef, task: dict[str, Any], provider: Provider, hub: ToolHub, *, system: str,
                    pricing: Pricing | None = None, result_chars: int = 12000, budget_usd: float | None = None) -> AgentResult:
    t0 = time.monotonic()
    pricing = pricing or Pricing()
    schema = _inline_refs(defn.output.model_json_schema())
    tools = hub.specs(defn.tools) + [{"name": SUBMIT, "description": f"Submit the final {defn.kind} result.",
                                      "input_schema": schema}]
    allowed = {t["name"] for t in tools}
    messages: list[dict[str, Any]] = [{"role": "user", "content": [{"type": "text", "text":
                                       "TASK (JSON):\n" + json.dumps(task, default=str, indent=1)}]}]
    res = AgentResult(defn.kind, "failed", model=provider.model, provider=provider.name)
    nudged = False
    for turn in range(defn.max_turns):
        res.turns = turn + 1
        try:
            llm = await provider.complete(system, messages, tools, defn.max_tokens)
        except Exception as exc:
            res.error = f"model call failed: {type(exc).__name__}: {exc}"[:500]
            break
        res.input_tokens += llm.input_tokens
        res.output_tokens += llm.output_tokens
        res.cost_usd = pricing.cost(provider.model, res.input_tokens, res.output_tokens)
        messages.append({"role": "assistant", "content": llm.content})
        res.transcript.append({"turn": turn, "assistant": llm.content})
        if budget_usd is not None and res.cost_usd > budget_usd:
            res.outcome, res.error = "budget", f"run exceeded its budget of ${budget_usd}"
            break
        uses = [b for b in llm.content if b["type"] == "tool_use"]
        if not uses:
            if nudged:
                res.error = "model stopped without calling submit_result"
                break
            nudged = True
            messages.append({"role": "user", "content": [{"type": "text", "text": f"Call {SUBMIT} now with your result."}]})
            continue
        results = []
        for u in uses:
            if u["name"] == SUBMIT:
                try:
                    res.output = defn.output.model_validate(u["input"]).model_dump()
                    res.outcome = "ok"
                except ValidationError as exc:
                    results.append({"type": "tool_result", "tool_use_id": u["id"], "is_error": True,
                                    "content": f"Invalid result, fix and resubmit: {exc.errors()[:5]}"})
                    continue
                res.seconds = round(time.monotonic() - t0, 2)
                return res
            if u["name"] not in allowed:
                results.append({"type": "tool_result", "tool_use_id": u["id"], "is_error": True,
                                "content": f"tool '{u['name']}' is not available to the {defn.kind} agent"})
                continue
            if res.tool_calls >= defn.max_tool_calls:
                results.append({"type": "tool_result", "tool_use_id": u["id"], "is_error": True,
                                "content": f"tool-call limit ({defn.max_tool_calls}) reached - submit your result now"})
                continue
            res.tool_calls += 1
            try:
                is_err, payload = await hub.call(u["name"], u.get("input") or {})
            except asyncio.TimeoutError:
                is_err, payload = True, "tool timed out"
            except Exception as exc:
                is_err, payload = True, f"{type(exc).__name__}: {exc}"[:500]
            res.transcript.append({"turn": turn, "tool": u["name"], "args": u.get("input"), "error": is_err,
                                   "result_chars": len(_render_result(payload, 10 ** 9))})
            results.append({"type": "tool_result", "tool_use_id": u["id"], "is_error": is_err,
                            "content": _render_result(payload, result_chars)})
        messages.append({"role": "user", "content": results})
    else:
        res.outcome, res.error = "limit", f"no result after {defn.max_turns} turns"
    res.seconds = round(time.monotonic() - t0, 2)
    return res
