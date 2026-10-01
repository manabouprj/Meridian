# MERIDIAN design documentation

This folder is the detailed design of MERIDIAN 1.0.0. It sits between the architecture documents (what and why) and the deployment runbooks (how to stand it up).

| Document | Contents | Audience |
| --- | --- | --- |
| [../HLD.md](../HLD.md) | High-level design: layers, flows, security, NFRs, cost model, migration | Architects, CISO |
| [ARCHITECTURE-DECISIONS.md](ARCHITECTURE-DECISIONS.md) | Architecture decision records (ADR-001 to ADR-014): context, decision, consequences | Architects, reviewers |
| [COMPONENT-DESIGN.md](COMPONENT-DESIGN.md) | Each module: responsibility, interfaces, key behaviour, failure handling, extension points | Engineers |
| [DATA-MODEL.md](DATA-MODEL.md) | Lake schema (OCSF-flat), store tables, state machines (generated) | Engineers, detection engineers |
| [API-REFERENCE.md](API-REFERENCE.md) | HTTP and MCP endpoints with required roles and scopes (generated) | Integrators |
| [CONFIGURATION.md](CONFIGURATION.md) | Every configuration section with defaults and guidance | Platform engineers |
| [ENVIRONMENT.md](ENVIRONMENT.md) | Environment variables and secrets (generated) | Platform engineers |
| [DETECTION-ENGINEERING.md](DETECTION-ENGINEERING.md) | Writing, testing and promoting rules; Sigma support matrix | Detection engineers |
| [../LLD-azure.md](../LLD-azure.md), [../LLD-aws.md](../LLD-aws.md) | Cloud low-level designs | Platform engineers |
| [../MCP-TOOLS.md](../MCP-TOOLS.md) | MCP tool reference (generated) | Agent developers |
| [../SECURITY.md](../SECURITY.md) | Controls, threat model, hardening | Security architects |

Deployment runbooks are in [../deployment/](../deployment/README.md).

**Generated documents.** Run `python scripts/gen_reference_docs.py` and `python scripts/gen_mcp_docs.py` after code changes. CI fails if the generated files differ from what is committed.
