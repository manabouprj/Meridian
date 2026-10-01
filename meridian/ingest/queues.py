"""Work notifications for new landing batches.

local  scan the landing store for batches not yet processed (development, single node)
sqs    Amazon SQS fed by S3 event notifications (s3:ObjectCreated:*), directly or via EventBridge
azure  Azure Storage Queue fed by Event Grid BlobCreated events from the landing account
Delivery is at-least-once everywhere; processing is idempotent (batch key -> deterministic lake file,
processed_batches table), so duplicates are harmless.
"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import unquote_plus, urlparse

log = logging.getLogger("meridian.queue")


@dataclass
class Message:
    keys: list[str]
    receipt: Any = None


class WorkQueue(Protocol):
    def receive(self, max_messages: int = 10) -> list[Message]: ...
    def ack(self, msg: Message) -> None: ...


class LocalQueue:
    def __init__(self, landing, store, limit: int = 200):
        self.landing, self.store, self.limit = landing, store, limit

    def receive(self, max_messages: int = 10) -> list[Message]:
        out = []
        for k in self.landing.list():
            if not self.store.batch_done(k):
                out.append(Message([k]))
                if len(out) >= min(max_messages, self.limit):
                    break
        return out

    def ack(self, msg: Message) -> None:
        return None


def s3_keys(body: dict[str, Any], prefix: str = "") -> list[str]:
    keys = []
    if body.get("detail-type") == "Object Created":               # EventBridge
        keys.append(body["detail"]["object"]["key"])
    for r in body.get("Records", []):                              # S3 notification
        if r.get("eventName", "").startswith("ObjectCreated"):
            keys.append(unquote_plus(r["s3"]["object"]["key"]))
    if "Message" in body and isinstance(body["Message"], str):     # SNS fan-out
        try:
            keys += s3_keys(json.loads(body["Message"]), "")
        except ValueError:
            pass
    strip = prefix.strip("/") + "/" if prefix else ""
    return [k[len(strip):] if strip and k.startswith(strip) else k for k in keys]


class SQSQueue:
    def __init__(self, queue_url: str, landing_prefix: str = "", client=None, wait_s: int = 10):
        import boto3
        self.url, self.prefix, self.wait_s = queue_url, landing_prefix, wait_s
        self.sqs = client or boto3.client("sqs")

    def receive(self, max_messages: int = 10) -> list[Message]:
        r = self.sqs.receive_message(QueueUrl=self.url, MaxNumberOfMessages=min(10, max_messages),
                                     WaitTimeSeconds=self.wait_s, VisibilityTimeout=900)
        out = []
        for m in r.get("Messages", []):
            try:
                keys = s3_keys(json.loads(m["Body"]), self.prefix)
            except ValueError:
                keys = []
            out.append(Message(keys, m["ReceiptHandle"]))
        return out

    def ack(self, msg: Message) -> None:
        self.sqs.delete_message(QueueUrl=self.url, ReceiptHandle=msg.receipt)


def eventgrid_keys(body: Any, container: str, prefix: str = "") -> list[str]:
    events = body if isinstance(body, list) else [body]
    keys = []
    for e in events:
        etype = e.get("eventType") or e.get("type")
        if etype != "Microsoft.Storage.BlobCreated":
            continue
        url = (e.get("data") or {}).get("url", "")
        path = unquote_plus(urlparse(url).path.lstrip("/"))
        if path.startswith(container + "/"):
            path = path[len(container) + 1:]
        strip = prefix.strip("/") + "/" if prefix else ""
        keys.append(path[len(strip):] if strip and path.startswith(strip) else path)
    return keys


class AzureQueue:
    """Storage Queues have no native dead-letter queue: a message delivered more than `max_attempts` times is
    copied to `<queue>-poison` and removed, so one bad batch can never block or loop the workers."""

    def __init__(self, account: str, queue: str, container: str, landing_prefix: str = "", client=None,
                 poison_client=None, max_attempts: int = 5):
        if client is None:
            from azure.identity import DefaultAzureCredential
            from azure.storage.queue import QueueClient
            cred = DefaultAzureCredential()
            client = QueueClient(f"https://{account}.queue.core.windows.net", queue, credential=cred)
            poison_client = poison_client or QueueClient(f"https://{account}.queue.core.windows.net", f"{queue}-poison",
                                                         credential=cred)
        self.q, self.poison, self.container, self.prefix = client, poison_client, container, landing_prefix
        self.max_attempts = max_attempts

    def receive(self, max_messages: int = 10) -> list[Message]:
        out = []
        for m in self.q.receive_messages(messages_per_page=min(32, max_messages), visibility_timeout=900,
                                         max_messages=max_messages):
            if (getattr(m, "dequeue_count", 0) or 0) > self.max_attempts:
                try:
                    if self.poison is not None:
                        self.poison.send_message(m.content)
                    self.q.delete_message(m)
                    log.error("landing message %s exceeded %d deliveries - moved to the poison queue", m.id,
                              self.max_attempts)
                except Exception as exc:     # never let parking a message stop the worker; it stays hidden for now
                    log.error("could not park landing message %s in the poison queue: %s", m.id, exc)
                continue
            raw = m.content
            try:
                body = json.loads(base64.b64decode(raw).decode()) if not str(raw).lstrip().startswith(("{", "[")) else json.loads(raw)
            except ValueError:
                body = {}
            out.append(Message(eventgrid_keys(body, self.container, self.prefix), m))
        return out

    def ack(self, msg: Message) -> None:
        self.q.delete_message(msg.receipt)


def open_queue(settings, landing, store) -> WorkQueue:
    q = settings.section("queue")
    kind = q.get("type", "local")
    if kind == "sqs":
        return SQSQueue(q["url"], q.get("landing_prefix", ""))
    if kind == "azure":
        return AzureQueue(q["account"], q["name"], q["container"], q.get("landing_prefix", ""),
                          max_attempts=int(q.get("max_attempts", 5)))
    return LocalQueue(landing, store)
