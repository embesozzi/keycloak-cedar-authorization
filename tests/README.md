# Demo and Use Cases

Keycloak with the Cedar provider, a `demo` realm, and four use cases checked by
[`e2e/evaluate.sh`](e2e/evaluate.sh).

Requires Java 17, Maven, Docker, `curl` and `jq`. From the repository root:

```sh
make up              # build, start Keycloak on http://localhost:8082, configure the realm
make test-e2e-run    # run the checks
make down            # stop Keycloak and delete its data
```

On Intel/AMD Docker hosts, use `CEDAR_ARCH=x86_64 make up`.

## Environment

| Item | Value |
|------|-------|
| Admin Console | `http://localhost:8082/admin`, `admin` / `admin` |
| Users | `alice` (`document-reader`), `bob` (`document-writer`), `carol` (`document-editor`); password = username |
| AI agent | client `spiffe://example.org/ns/agents/sa/planner-agent`, role `support-agent` |
| `documents-api` | resource `document-1` (type `Document`), scopes `read`, `write` |
| `mcp-server` | tools `get_customer`, `list_customers`, `delete_customer` (type `Tool`), scope `call` |

Client secrets are set in [`bootstrap.sh`](bootstrap.sh). They are demo values; use them only locally.

## The Request

The PEP calls `POST /realms/demo/authzen/access/v1/evaluation` with the token of the resource server
(`documents-api` for cases 1 to 3, `mcp-server` for case 4). Only subject, action and context change
between the cases:

```json
{
  "subject":  { "type": "user", "id": "alice" },
  "resource": { "type": "Document", "id": "document-1" },
  "action":   { "name": "read" },
  "context":  { }
}
```

## 1. Users by Role

Readers may read, writers may write. Roles come from Keycloak, never from the request.
Policy: [`documents.cedar`](policies/documents-api/documents.cedar)

```cedar
@id("document-readers-read")
permit (
  principal in Keycloak::Role::"document-reader",
  action == Documents::Action::"read",
  resource is Documents::Document
);
```

| Subject | Action | Decision |
|---------|--------|----------|
| alice | read | true |
| alice | write | false |
| bob | write | true |
| alice, claiming `document-writer` in `subject.properties` | write | false |

## 2. Authentication Context

Editors may write only after a passkey login. The PEP sends `acr` and `amr` in the context.
Policy: [`document-write-passkey.cedar`](policies/documents-api/document-write-passkey.cedar)

```cedar
@id("editors-write-with-passkey")
permit (
  principal in Keycloak::Role::"document-editor",
  action == Documents::Action::"write",
  resource is Documents::Document
)
when
{
  context has acr &&
  context.acr == "inherence" &&
  context has amr &&
  context.amr.contains("passkeys")
};
```

| Subject | Context | Decision |
|---------|---------|----------|
| carol | `{ "acr": "inherence", "amr": ["passkeys", "mfa"] }` | true |
| carol | `{ "acr": "inherence", "amr": ["pwd"] }` | false |

## 3. AI Agent Reads Documents

Only the planner agent, identified by its SPIFFE ID, may read documents.
Policy: [`planner-agent-read.cedar`](policies/documents-api/planner-agent-read.cedar)

```cedar
@id("planner-agent-read")
permit (
  principal is Keycloak::Client,
  action == Documents::Action::"read",
  resource is Documents::Document
)
when { principal.clientId == "spiffe://example.org/ns/agents/sa/planner-agent" };
```

| Subject | Action | Decision |
|---------|--------|----------|
| planner agent | read | true |
| planner agent | write | false |

## 4. AI Agent Calls MCP Tools

Support agents may call the customer read tools; no agent may delete a customer. Each tool is a Keycloak
resource of type `Tool`, named after the tool. Request: `"resource": { "type": "Tool", "id": "get_customer" }`,
`"action": { "name": "call" }`.
Policy: [`tools.cedar`](policies/mcp-server/tools.cedar)

```cedar
@id("support-agents-call-customer-read-tools")
permit (principal is Keycloak::Client, action == Mcp::Action::"call", resource is Mcp::Tool)
when {
  resource in [Mcp::Tool::"get_customer", Mcp::Tool::"list_customers"] &&
  principal.roles.contains("support-agent") &&
  context has scope && context.scope.contains("mcp:tools")
};

@id("no-agent-calls-delete-customer")
forbid (principal is Keycloak::Client, action == Mcp::Action::"call", resource == Mcp::Tool::"delete_customer");
```

| Tool | Context | Decision |
|------|---------|----------|
| `get_customer`, `list_customers` | `{ "scope": ["mcp:tools"] }` | true |
| `get_customer` | `{ }` | false |
| `delete_customer` | `{ "scope": ["mcp:tools"] }` | false, the forbid wins |

## How an AI Agent Is Identified

1. The agent gets a token with client credentials; its `sub` is the agent's service account user.
2. The PEP sends that `sub` as the subject: `{ "type": "user", "id": "<sub>" }`.
3. The provider sees a service account and uses its client as the principal, `Keycloak::Client`.

Type `client` is not used because Keycloak accepts it only when the subject is the caller itself.
