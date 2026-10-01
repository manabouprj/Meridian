# Word editions

Generated from the markdown in `docs/` by `NODE_PATH=$(npm root -g) node scripts/build_docx.js` (requires the `docx`
npm package). The markdown is the source of truth: edit it, then rebuild these files.

| File | Source |
| --- | --- |
| MERIDIAN-Executive-Review.docx | docs/EXECUTIVE_REVIEW.md |
| MERIDIAN-HLD.docx | docs/HLD.md + SECURITY.md + PEER_REVIEW.md |
| MERIDIAN-LLD-Azure.docx | docs/LLD-azure.md + OPERATIONS.md + MCP-TOOLS.md |
| MERIDIAN-LLD-AWS.docx | docs/LLD-aws.md + OPERATIONS.md + MCP-TOOLS.md |
| MERIDIAN-Detailed-Design.docx | docs/design/*.md |
| MERIDIAN-Deployment-Guide.docx | docs/deployment/*.md |

The PDF build documents (AZ-00, AWS-00, INT-00, LOG-00) are in [../pdf](../pdf/README.md).
