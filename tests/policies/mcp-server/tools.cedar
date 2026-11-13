// Resource server: mcp-server (schema.cedarschema, namespace Mcp)
// MCP tools are Keycloak resources of type Tool, named after the tool: Mcp::Tool::"get_customer".
// Agents with the role support-agent may call the customer read tools, when their token grants mcp:tools.
@id("support-agents-call-customer-read-tools")
permit (
  principal is Keycloak::Client,
  action == Mcp::Action::"call",
  resource is Mcp::Tool
)
when
{
  resource in [Mcp::Tool::"get_customer", Mcp::Tool::"list_customers"] &&
  principal.roles.contains("support-agent") &&
  context has scope &&
  context.scope.contains("mcp:tools")
};

// Agents with the role tool-admin may call every tool...
@id("tool-admins-call-all-tools")
permit (
  principal is Keycloak::Client,
  action == Mcp::Action::"call",
  resource is Mcp::Tool
)
when { principal.roles.contains("tool-admin") };

// ...except delete_customer: no agent may call it, whatever other policies allow.
@id("no-agent-calls-delete-customer")
forbid (
  principal is Keycloak::Client,
  action == Mcp::Action::"call",
  resource == Mcp::Tool::"delete_customer"
);
