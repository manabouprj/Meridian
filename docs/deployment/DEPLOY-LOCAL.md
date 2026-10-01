# Deploy locally: evaluation and single-host pilot

## 1. Ten-minute evaluation (fictional data, no cloud, no model)

```bash
git clone https://github.com/manabouprj/Meridian.git && cd Meridian
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m meridian demo --serve
```

* **What it does.** It generates about 3,000 events for a fictional company (Kestrel Logistics, `*.example`), ingests them, raises alerts, triages them with the offline analyst and opens cases. Then it starts the console on http://127.0.0.1:8090 and prints one-time sign-in keys for the admin, responder and analyst roles.
* **Verify:**
  * the output ends with `audit chain valid`;
  * you can sign in with the responder key;
  * the phishing case shows pending `isolate_device` and `revoke_sessions` approvals;
  * approving one records a dry-run execution in the case timeline.

## 2. Single-host pilot with Docker Compose (your data)

Suitable for a proof of value on one Linux VM: 4 vCPU, 16 GB RAM and 200 GB disk handle roughly 20 GB/day. This setup is **not** highly available. Use the cloud runbooks for production.

### Step 1: build the image

```bash
docker build -t meridian:1.0.0 .
```

**Verify:** `docker run --rm meridian:1.0.0 rules --check` prints `30 rules loaded, 0 error(s)`.

### Step 2: create secrets

```bash
cp .env.example .env
python -c "import secrets; [print(n, secrets.token_urlsafe(32)) for n in ('admin','responder','analyst','session','ingest','edl','metrics')]"
```

Edit `.env` and replace every `change-me...` value. API keys use the format `role:key,role:key`, for example `admin:<key>,responder:<key>,analyst:<key>`.

**Verify:** `grep -c change-me .env` prints `0`. If any placeholder remains, `/readyz` refuses traffic.

### Step 3: configure

Edit `config/meridian.yaml`:

* `org` (name, industry, crown jewels);
* `sources` (keep only the ones you will send);
* `response` (leave `dry_run: true`).

Put your CMDB and identity CSVs in `config/` (`assets.csv`, `identities.csv`) and intel files in `config/intel/`.

To use Claude, set the `model` section to Foundry or Bedrock and give the container credentials:

* **Foundry:** `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_CLIENT_SECRET` for a service principal with the Azure AI User role.
* **Bedrock:** an instance role, or `AWS_*` variables.

Otherwise keep `provider: scripted`.

**Verify:** `docker compose run --rm api doctor` shows no FAIL lines.

### Step 4: start

```bash
docker compose up -d
docker compose ps
curl -s http://127.0.0.1:8090/readyz
```

**Verify:** all five services are `running`, and `/readyz` returns `{"ready": true, ...}`.

### Step 5: send test data

```bash
export MERIDIAN_INGEST_SECRET=<the ingest secret from .env>
python scripts/push_events.py --url http://127.0.0.1:8090 --source firewall \
  --line "CEF:0|Vendor|FW|1|100|deny|5|src=203.0.113.5 dst=10.0.0.1 dpt=3389"
```

Point a firewall's syslog (CEF) at the host on port 5514 (UDP or TCP).

**Verify:**

* the push returns `202 {'accepted': 1, ...}`;
* `docker compose logs worker | tail` shows the batch;
* within a minute, `docker compose run --rm api query '{"classes":[4001],"last_minutes":60,"limit":5}'` returns the event.

### Step 6: day-2 basics

| Task | Command |
| --- | --- |
| Logs | `docker compose logs -f worker agents scheduler` |
| Validate the audit chain | `docker compose run --rm api verify-audit` |
| Re-process a day after a mapper fix | `docker compose run --rm api replay --prefix firewall/2026/10/01` |
| Back up | Stop the stack, then back up the `meridian-data` volume (lake, landing, SQLite) |
| Stop | `docker compose down` (data is kept in the volume) |
