"""Landing formats, idempotent processing, enrichment, cloud queue notifications."""
import base64
import gzip
import io
import json
from datetime import datetime, timezone

from conftest import ROOT

from meridian.context import Asset, Context, Identity, Indicator
from meridian.detect import StreamDetector, load_rules
from meridian.ingest import Pipeline, read_batch, write_batch
from meridian.ingest.queues import eventgrid_keys, s3_keys
from meridian.lake import LocalStore
from meridian.store import Store


def test_read_batch_formats():
    j = json.dumps({"Records": [{"a": 1}, {"a": 2}]}).encode()
    assert len(list(read_batch("x/ct.json.gz", gzip.compress(j)))) == 2
    assert list(read_batch("x/a.jsonl", b'{"a":1}\n{"records":[{"b":2},{"b":3}]}\n')) == [{"a": 1}, {"b": 2}, {"b": 3}]
    assert list(read_batch("x/s.log", b"CEF:0|a|b|1|x|y|3|src=1.2.3.4\n\n")) == ["CEF:0|a|b|1|x|y|3|src=1.2.3.4"]
    import fastavro
    buf = io.BytesIO()
    schema = {"type": "record", "name": "EventData", "fields": [{"name": "Body", "type": "bytes"}]}
    fastavro.writer(buf, schema, [{"Body": json.dumps({"records": [{"c": 1}, {"c": 2}]}).encode()}])
    assert list(read_batch("eh/capture.avro", buf.getvalue())) == [{"c": 1}, {"c": 2}]


def _pipe(tmp_path):
    rules, _ = load_rules([ROOT / "config" / "rules"])
    ctx = Context([Asset("DB-1", "db-1", criticality=5, aliases=["db-1.corp.example"])],
                  [Identity("jdoe", upn="jdoe@corp.example", privileged=True)],
                  [Indicator("evil.example", "domain", "ISAC")])
    landing, lake = LocalStore(str(tmp_path / "landing")), LocalStore(str(tmp_path / "lake"))
    store = Store(f"sqlite:///{tmp_path}/m.db")
    return Pipeline([{"key": "mde", "format": "mde"}, {"key": "dns", "format": "ocsf"}], landing, lake, store, ctx,
                    StreamDetector(rules)), landing, lake, store


def test_process_is_idempotent_and_enriches(tmp_path):
    pipe, landing, lake, store = _pipe(tmp_path)
    now = datetime.now(timezone.utc).isoformat()
    rec = {"category": "AdvancedHunting-DeviceProcessEvents", "properties": {"Timestamp": now, "DeviceName": "db-1.corp.example",
           "FileName": "powershell.exe", "ProcessCommandLine": "powershell -enc AAAA", "AccountUpn": "jdoe@corp.example"}}
    key = write_batch(landing, "mde", [rec, rec, "garbage line"])
    r1 = pipe.process(key)
    assert r1.events == 1 and r1.rejected == 1 and len(r1.new_alerts) == 1
    files = sorted(lake.list("events"))
    assert pipe.process(key).skipped == "already processed"
    r3 = pipe.process(key, force=True)
    assert sorted(lake.list("events")) == files and r3.new_alerts == []          # same file, no duplicate alert
    alert = store.get_alert(r1.new_alerts[0])
    tags = alert["data"]["sample"][0]["tags"]
    assert "crown_jewel" in tags and "privileged_user" in tags and "asset:DB-1" in tags


def test_ioc_enrichment_parent_domain(tmp_path):
    pipe, landing, lake, store = _pipe(tmp_path)
    rec = {"class_uid": 4003, "time": int(datetime.now(timezone.utc).timestamp() * 1000), "query": {"hostname": "a.b.evil.example"},
           "device": {"hostname": "ws1"}}
    r = pipe.process(write_batch(landing, "dns", [rec]))
    assert any(store.get_alert(a)["rule_id"] == "mer-net-ioc-hit" for a in r.new_alerts)


def test_unknown_prefix_is_recorded_not_lost(tmp_path):
    pipe, landing, lake, store = _pipe(tmp_path)
    key = write_batch(landing, "unconfigured", [{"a": 1}])
    assert pipe.process(key).skipped and store.batch_done(key)


def test_cloud_notifications():
    s3 = {"Records": [{"eventName": "ObjectCreated:Put", "s3": {"object": {"key": "landing/mde/2026/10/01/a%2Bb.jsonl.gz"}}}]}
    assert s3_keys(s3, "landing") == ["mde/2026/10/01/a+b.jsonl.gz"]
    eb = {"detail-type": "Object Created", "detail": {"object": {"key": "mde/x.jsonl.gz"}}}
    assert s3_keys(eb) == ["mde/x.jsonl.gz"]
    eg = [{"eventType": "Microsoft.Storage.BlobCreated",
           "data": {"url": "https://acct.blob.core.windows.net/landing/entra/2026/x.avro"}}]
    assert eventgrid_keys(eg, "landing") == ["entra/2026/x.avro"]
    assert base64  # (Azure queue messages are base64 JSON; decoded in AzureQueue.receive)


def test_failed_batch_is_recorded_and_replay_is_idempotent(tmp_path, monkeypatch):
    from conftest import demo_overrides

    from meridian.cli import drain_landing
    from meridian.demo import write_context
    from meridian.ingest.landing import write_batch
    from meridian.runtime import Runtime
    write_context(tmp_path / "context")
    rt = Runtime.load(None, **demo_overrides(tmp_path))
    key = write_batch(rt.landing, "entra", [{"bad": "record"}])
    real = rt.pipeline.process

    def boom(k, force=False):
        raise RuntimeError("mapper bug")
    monkeypatch.setattr(rt.pipeline, "process", boom)
    tot = drain_landing(rt)
    assert tot["failed"] == 1 and rt.store.batch_done(key)            # recorded, no infinite retry loop
    monkeypatch.setattr(rt.pipeline, "process", real)
    first = rt.pipeline.process(key, force=True)
    second = rt.pipeline.process(key, force=True)
    assert first.events == second.events


def test_azure_activity_source_maps_through_the_pipeline(tmp_path):
    """The shipped Azure example config must actually turn Activity log records into API Activity events."""
    import yaml
    from conftest import ROOT, demo_overrides

    from meridian.demo import write_context
    from meridian.ingest.landing import write_batch
    from meridian.runtime import Runtime
    write_context(tmp_path / "context")
    src = next(s for s in yaml.safe_load((ROOT / "config/examples/azure.yaml").read_text())["sources"]
               if s["key"] == "azure-activity")
    rt = Runtime.load(None, **{**demo_overrides(tmp_path), "sources": [src]})
    rec = {"records": [{"time": "2026-10-01T10:00:00Z", "operationName": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
                        "resourceId": "/subscriptions/0000/resourceGroups/rg", "callerIpAddress": "203.0.113.9",
                        "resultType": "Success", "category": "Administrative",
                        "identity": {"claims": {"name": "ops@contoso.example"}}}]}
    key = write_batch(rt.landing, "azure-activity", [rec])
    r = rt.pipeline.process(key)
    assert r.events == 1 and r.rejected == 0


def test_syslog_buffer_keeps_lines_when_storage_fails(tmp_path):
    from meridian.ingest.syslog import Buffer
    from meridian.lake.storage import LocalStore

    class Flaky(LocalStore):
        fail = True

        def put(self, key, data):
            if self.fail:
                raise OSError("storage unavailable")
            return super().put(key, data)
    store = Flaky(str(tmp_path / "landing"))
    buf = Buffer(store, "firewall", flush_seconds=0, max_lines=2)
    buf.add("CEF:0|a|b|1|x|y|5|src=203.0.113.1")
    buf.add("CEF:0|a|b|1|x|y|5|src=203.0.113.2")
    assert buf.due()
    import pytest
    with pytest.raises(OSError):
        buf.flush()
    assert len(buf.lines) == 2                                   # nothing lost
    store.fail = False
    assert buf.flush() and buf.lines == [] and buf.flushed == 2
