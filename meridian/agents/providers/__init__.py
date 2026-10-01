"""Model providers. Internal message format = Anthropic Messages (content blocks); adapters translate.

provider               where                          auth
anthropic_foundry      Claude in Microsoft Foundry    Entra ID (managed identity, scope https://ai.azure.com/.default) or key
anthropic_bedrock      Claude in Amazon Bedrock       IAM role (bedrock-runtime InvokeModel; inference profiles)
bedrock_converse       any Bedrock model (Converse)   IAM role
foundry_openai         OpenAI-compatible models in Foundry (chat/completions v1)   Entra ID
scripted               deterministic offline analyst (tests, demo, and the degraded mode when the model
                       budget is exhausted or the model endpoint is down)
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class LLMResponse:
    content: list[dict[str, Any]]
    stop_reason: str = "end_turn"
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""


class Provider(Protocol):
    name: str
    model: str

    async def complete(self, system: str, messages: list[dict], tools: list[dict], max_tokens: int) -> LLMResponse: ...


def _blocks(content) -> list[dict[str, Any]]:
    out = []
    for b in content:
        d = b.model_dump() if hasattr(b, "model_dump") else dict(b)
        if d.get("type") == "text":
            out.append({"type": "text", "text": d.get("text", "")})
        elif d.get("type") == "tool_use":
            out.append({"type": "tool_use", "id": d["id"], "name": d["name"], "input": d.get("input") or {}})
    return out


@dataclass
class AnthropicProvider:
    """Claude through the Anthropic Messages API as served by Microsoft Foundry or Amazon Bedrock."""
    client: Any
    model: str
    name: str = "anthropic"
    temperature: float = 0.0

    async def complete(self, system, messages, tools, max_tokens) -> LLMResponse:
        r = await self.client.messages.create(model=self.model, system=system, messages=messages, tools=tools,
                                              max_tokens=max_tokens, temperature=self.temperature)
        return LLMResponse(_blocks(r.content), r.stop_reason or "end_turn", r.usage.input_tokens, r.usage.output_tokens, self.model)


def anthropic_foundry(cfg: dict[str, Any]) -> AnthropicProvider:
    from anthropic import AsyncAnthropicFoundry
    kw: dict[str, Any] = {"resource": cfg["resource"]}
    if cfg.get("api_key"):
        kw["api_key"] = cfg["api_key"]
    else:                                             # managed identity / workload identity
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        kw["azure_ad_token_provider"] = get_bearer_token_provider(DefaultAzureCredential(), "https://ai.azure.com/.default")
    return AnthropicProvider(AsyncAnthropicFoundry(**kw), cfg.get("deployment") or cfg["model"], "anthropic_foundry")


def anthropic_bedrock(cfg: dict[str, Any]) -> AnthropicProvider:
    """Claude on Amazon Bedrock through bedrock-runtime (InvokeModel): reachable through the bedrock-runtime VPC
    interface endpoint, IAM-authorised with bedrock:InvokeModel, and works with cross-region inference profiles
    (model = profile id such as global.anthropic.claude-...). `endpoint: mantle` selects the Bedrock Messages API
    endpoint (bedrock-mantle.<region>.api.aws) instead, which is NOT covered by the bedrock-runtime VPC endpoint."""
    region = cfg.get("region", "us-east-1")
    if cfg.get("endpoint") == "mantle":
        from anthropic import AsyncAnthropicBedrockMantle
        return AnthropicProvider(AsyncAnthropicBedrockMantle(aws_region=region), cfg["model"], "anthropic_bedrock")
    from anthropic import AsyncAnthropicBedrock
    return AnthropicProvider(AsyncAnthropicBedrock(aws_region=region), cfg["model"], "anthropic_bedrock")


@dataclass
class BedrockConverseProvider:
    model: str
    region: str = "us-east-1"
    client: Any = None
    name: str = "bedrock_converse"

    def __post_init__(self):
        if self.client is None:
            import boto3
            self.client = boto3.client("bedrock-runtime", region_name=self.region)

    @staticmethod
    def to_converse(messages: list[dict]) -> list[dict]:
        out = []
        for m in messages:
            content = m["content"] if isinstance(m["content"], list) else [{"type": "text", "text": m["content"]}]
            blocks = []
            for b in content:
                if b["type"] == "text":
                    blocks.append({"text": b["text"]})
                elif b["type"] == "tool_use":
                    blocks.append({"toolUse": {"toolUseId": b["id"], "name": b["name"], "input": b["input"]}})
                elif b["type"] == "tool_result":
                    txt = b["content"] if isinstance(b["content"], str) else json.dumps(b["content"])
                    blocks.append({"toolResult": {"toolUseId": b["tool_use_id"], "content": [{"text": txt}],
                                                  "status": "error" if b.get("is_error") else "success"}})
            out.append({"role": m["role"], "content": blocks})
        return out

    async def complete(self, system, messages, tools, max_tokens) -> LLMResponse:
        req = {"modelId": self.model, "system": [{"text": system}], "messages": self.to_converse(messages),
               "inferenceConfig": {"maxTokens": max_tokens, "temperature": 0},
               "toolConfig": {"tools": [{"toolSpec": {"name": t["name"], "description": (t.get("description") or t["name"])[:4000],
                                                      "inputSchema": {"json": t["input_schema"]}}} for t in tools]}}
        r = await asyncio.to_thread(self.client.converse, **req)
        blocks = []
        for b in r["output"]["message"]["content"]:
            if "text" in b:
                blocks.append({"type": "text", "text": b["text"]})
            elif "toolUse" in b:
                blocks.append({"type": "tool_use", "id": b["toolUse"]["toolUseId"], "name": b["toolUse"]["name"],
                               "input": b["toolUse"].get("input") or {}})
        u = r.get("usage", {})
        stop = {"tool_use": "tool_use", "end_turn": "end_turn", "max_tokens": "max_tokens"}.get(r.get("stopReason"), "end_turn")
        return LLMResponse(blocks, stop, u.get("inputTokens", 0), u.get("outputTokens", 0), self.model)


@dataclass
class FoundryOpenAIProvider:
    """OpenAI-compatible models deployed in Microsoft Foundry (v1 chat completions)."""
    resource: str
    deployment: str
    token_provider: Any = None
    transport: Any = None
    name: str = "foundry_openai"

    @property
    def model(self) -> str:
        return self.deployment

    @staticmethod
    def to_openai(system: str, messages: list[dict]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}]
        for m in messages:
            content = m["content"] if isinstance(m["content"], list) else [{"type": "text", "text": m["content"]}]
            if m["role"] == "assistant":
                text = "".join(b["text"] for b in content if b["type"] == "text")
                calls = [{"id": b["id"], "type": "function", "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                         for b in content if b["type"] == "tool_use"]
                msg: dict[str, Any] = {"role": "assistant", "content": text or None}
                if calls:
                    msg["tool_calls"] = calls
                out.append(msg)
            else:
                for b in content:
                    if b["type"] == "tool_result":
                        txt = b["content"] if isinstance(b["content"], str) else json.dumps(b["content"])
                        out.append({"role": "tool", "tool_call_id": b["tool_use_id"], "content": txt})
                texts = [b["text"] for b in content if b["type"] == "text"]
                if texts:
                    out.append({"role": "user", "content": "\n".join(texts)})
        return out

    async def complete(self, system, messages, tools, max_tokens) -> LLMResponse:
        import httpx
        if self.token_provider is None:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
            self.token_provider = get_bearer_token_provider(DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default")
        body = {"model": self.deployment, "messages": self.to_openai(system, messages), "max_completion_tokens": max_tokens,
                "tools": [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""),
                                                            "parameters": t["input_schema"]}} for t in tools]}
        kw = {"transport": self.transport} if self.transport else {}
        async with httpx.AsyncClient(timeout=120, trust_env=True, **kw) as c:
            r = await c.post(f"https://{self.resource}.openai.azure.com/openai/v1/chat/completions", json=body,
                             headers={"Authorization": f"Bearer {self.token_provider()}"})
        r.raise_for_status()
        d = r.json()
        msg = d["choices"][0]["message"]
        blocks: list[dict] = [{"type": "text", "text": msg["content"]}] if msg.get("content") else []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"]["arguments"] or "{}")
            except ValueError:
                args = {}
            blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["function"]["name"], "input": args})
        u = d.get("usage") or {}
        return LLMResponse(blocks, "tool_use" if msg.get("tool_calls") else "end_turn", u.get("prompt_tokens", 0),
                           u.get("completion_tokens", 0), self.deployment)


def make_provider(cfg: dict[str, Any]) -> Provider:
    kind = cfg.get("provider", "scripted")
    if kind == "anthropic_foundry":
        return anthropic_foundry(cfg)
    if kind == "anthropic_bedrock":
        return anthropic_bedrock(cfg)
    if kind == "bedrock_converse":
        return BedrockConverseProvider(cfg["model"], cfg.get("region", "us-east-1"))
    if kind == "foundry_openai":
        return FoundryOpenAIProvider(cfg["resource"], cfg["deployment"])
    if kind == "scripted":
        from .scripted import ScriptedProvider
        return ScriptedProvider()
    raise ValueError(f"unknown model provider '{kind}'")


@dataclass
class Pricing:
    """USD per million tokens. Set real prices from your Foundry / Bedrock price sheet in config (model.pricing)."""
    table: dict[str, tuple[float, float]] = field(default_factory=dict)

    def cost(self, model: str, inp: int, out: int) -> float:
        pin, pout = self.table.get(model, (0.0, 0.0))
        return round(inp / 1e6 * pin + out / 1e6 * pout, 6)
