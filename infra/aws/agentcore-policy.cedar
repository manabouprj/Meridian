// Amazon Bedrock AgentCore Policy (Cedar) for the MERIDIAN MCP servers registered as Gateway targets.
// Default deny; each agent identity gets only its role's tools. Response tools can only REQUEST containment -
// MERIDIAN still requires a human approval before anything runs.
// Action names follow AgentCore's "<target>___<tool>" convention - check them in your gateway's tool list.

permit (principal, action in [
  AgentCore::Action::"meridian-lake___search_events",
  AgentCore::Action::"meridian-lake___aggregate_events",
  AgentCore::Action::"meridian-lake___entity_timeline",
  AgentCore::Action::"meridian-lake___describe_schema",
  AgentCore::Action::"meridian-context___lookup_asset",
  AgentCore::Action::"meridian-context___lookup_identity",
  AgentCore::Action::"meridian-context___check_indicator",
  AgentCore::Action::"meridian-context___get_alert",
  AgentCore::Action::"meridian-context___related_alerts"
], resource)
when { principal.hasTag("groups") && principal.getTag("groups").contains("meridian-agents") };

permit (principal, action in [
  AgentCore::Action::"meridian-lake___ioc_sweep",
  AgentCore::Action::"meridian-cases___get_case",
  AgentCore::Action::"meridian-cases___add_case_note",
  AgentCore::Action::"meridian-response___list_actions",
  AgentCore::Action::"meridian-response___request_containment"
], resource)
when { principal.hasTag("groups") && principal.getTag("groups").contains("meridian-investigators") };

// Never allow agents to request containment of internal ranges via the block list (MERIDIAN also refuses it).
forbid (principal, action == AgentCore::Action::"meridian-response___request_containment", resource)
when { context.input.action == "block_indicator" && context.input.target like "10.*" };
