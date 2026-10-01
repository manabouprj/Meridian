# PDF build documents

Generated from the markdown sources by `python scripts/build_pdf_docs.py [AZ-00] [AWS-00] [INT-00] [LOG-00]` (Playwright
Chromium and pdfplumber; IBM Plex fonts installed locally give the intended typography). The markdown is the source
of truth: edit it, then rebuild. The agent tables and constitutions in Appendix A are generated from
`meridian/agents/definitions.py`, so the printed SHA-256 values always match `meridian baseline`.

| File | Source | Content |
| --- | --- | --- |
| MERIDIAN-AZ-00-Foundry-Design-and-Deployment.pdf | docs/cloud/MERIDIAN-AZ-00.md | Azure + Microsoft Foundry: design, residency, setup S0-S7, verification, agent constitutions |
| MERIDIAN-AWS-00-Bedrock-Design-and-Deployment.pdf | docs/cloud/MERIDIAN-AWS-00.md | AWS + Amazon Bedrock (me-central-1): the same, for AWS |
| MERIDIAN-LOG-00-Log-Ingestion-Normalisation-Retention.pdf | docs/ingestion/MERIDIAN-LOG-00.md | Log ingestion for hybrid estates: six paths, Windows/Sysmon, normalisation, retention and rotation, sizing, operations |
| MERIDIAN-LODESTAR-INT-00-Integration-Design-and-Deployment.pdf | docs/integration/MERIDIAN-LODESTAR-INT-00.md | MERIDIAN to LODESTAR: HLD, contract, identity mapping, deployment, security, operations, evidence |
