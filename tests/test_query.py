"""Portable, injection-safe queries and the three engines."""
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from meridian.lake import LocalStore, QueryError, QuerySpec, compile_kql, compile_sql, write_events
from meridian.lake.engines import ADXEngine, AthenaEngine, DuckDBEngine
from meridian.ocsf import event

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def test_fields_and_values_cannot_inject():
    with pytest.raises(ValueError):
        QuerySpec(where=[{"field": "user; DROP TABLE x", "op": "eq", "value": "a"}])
    with pytest.raises(ValueError):
        QuerySpec(fields=["raw"])                     # raw is not queryable by agents
    spec = QuerySpec(last_minutes=10, where=[{"field": "user", "op": "eq", "value": "x' OR '1'='1"}])
    sql, params = compile_sql(spec, "t", NOW)
    assert "x' OR" not in sql and "x' OR '1'='1" in params
    kql, kp = compile_kql(spec, "T", NOW)
    assert "x' OR" not in kql and "x' OR '1'='1" in kp.values() and kql.startswith("declare query_parameters(")


def test_numeric_and_window_validation():
    with pytest.raises(ValueError):
        QuerySpec(where=[{"field": "dst_port", "op": "eq", "value": "22 OR 1=1"}])
    with pytest.raises(QueryError):
        compile_sql(QuerySpec(since=NOW - timedelta(days=500), until=NOW), "t", NOW)
    sql, params = compile_sql(QuerySpec(classes=[3002], last_minutes=60, group_by=["user"], having_min_count=5), "t", NOW)
    assert 'GROUP BY "user"' in sql and "HAVING count(*) >= ?" in sql and params[-1] == 5 and 3002 in params


def test_like_wildcards_escaped():
    sql, params = compile_sql(QuerySpec(where=[{"field": "url", "op": "contains", "value": "50%_off"}]), "t", NOW)
    assert "%50\\%\\_off%" in params


@pytest.fixture
def lake(tmp_path):
    st = LocalStore(str(tmp_path))
    evs = [event(3002, time=NOW - timedelta(minutes=i), user="bob@x.example", src_ip="203.0.113.5", status="Failure", source="t")
           for i in range(1, 13)]
    evs.append(event(1007, time=NOW - timedelta(minutes=2), process_cmdline="powershell -enc AAA", device="ws1", source="t"))
    write_events(st, evs, "b1")
    return str(tmp_path)


def test_duckdb_engine(lake):
    e = DuckDBEngine(lake)
    rows = e.run(QuerySpec(classes=[3002], last_minutes=60, where=[{"field": "status", "op": "eq", "value": "failure"}],
                           group_by=["user", "src_ip"], having_min_count=5), now=NOW)
    assert rows[0]["event_count"] == 12 and rows[0]["first_seen"].endswith("+00:00")
    rows = e.run(QuerySpec(last_minutes=60, where=[{"field": "process_cmdline", "op": "contains", "value": "-ENC"}]), now=NOW)
    assert rows and rows[0]["device"] == "ws1"
    assert DuckDBEngine(lake + "/empty").run(QuerySpec(last_minutes=5), now=NOW) == []


def test_athena_engine_with_stubbed_client():
    import boto3
    from botocore.stub import ANY, Stubber
    client = boto3.client("athena", region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="y")
    st = Stubber(client)
    st.add_response("start_query_execution", {"QueryExecutionId": "q1"},
                    {"QueryString": ANY, "QueryExecutionContext": {"Database": "meridian"}, "WorkGroup": "meridian",
                     "ExecutionParameters": ANY})
    st.add_response("get_query_execution", {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}}, {"QueryExecutionId": "q1"})
    st.add_response("get_query_results", {"ResultSet": {"Rows": [
        {"Data": [{"VarCharValue": "user"}, {"VarCharValue": "event_count"}]},
        {"Data": [{"VarCharValue": "bob@x.example"}, {"VarCharValue": "12"}]}]}}, {"QueryExecutionId": "q1", "MaxResults": 1000})
    with st:
        rows = AthenaEngine("meridian", client=client).run(QuerySpec(group_by=["user"], last_minutes=60), now=NOW)
    assert rows == [{"user": "bob@x.example", "event_count": "12"}]


def test_adx_engine_sends_parameters():
    seen = {}

    def handler(req):
        seen.update(json.loads(req.content))
        return httpx.Response(200, json={"Tables": [{"Columns": [{"ColumnName": "user"}, {"ColumnName": "event_count"}],
                                                     "Rows": [["bob@x.example", 12]]}]})
    e = ADXEngine("https://c.region.kusto.windows.net", "meridian", token_provider=lambda: "tok",
                  transport=httpx.MockTransport(handler))
    rows = e.run(QuerySpec(group_by=["user"], last_minutes=60, where=[{"field": "user", "op": "eq", "value": "bob"}]), now=NOW)
    assert rows == [{"user": "bob@x.example", "event_count": 12}]
    assert seen["db"] == "meridian" and "bob" in seen["properties"]["Parameters"].values() and "bob" not in seen["csl"]
