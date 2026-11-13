# Demo and Use Cases

The demo runs Keycloak with the Cedar provider and a `demo` realm with users, an AI agent and two resource
servers. Each use case below shows the policy, the AuthZEN request and the expected decisions; all of them
are checked by [`cli-tests/tests-evaluate.sh`](cli-tests/tests-evaluate.sh).

Requires Java 17, Maven, Docker, `curl` and `jq`. Run from the repository root:

```sh
make up              # build, start Keycloak on http://localhost:8082, configure the demo realm
make test-e2e-run    # run the AuthZEN checks of the use cases
make down            # stop Keycloak and delete its data
```

On Intel/AMD Docker hosts, use `CEDAR_ARCH=x86_64 make up` (the default is `aarch64`).

## Environment

| Item | Value |
|------|-------|
| Admin Console | `http://localhost:8082/admin`, user `admin`, password `admin` |
| Realm | `demo` |
| Users | `alice` (role `document-reader`), `bob` (role `document-writer`), `carol` (role `document-editor`); password = username |
| AI agent | client `spiffe://example.org/ns/agents/sa/planner-agent`, secret `planner-agent-secret`, role `support-agent` |
| Resource server `documents-api` | secret `documents-api-secret`; resource `document-1` of type `Document`, scopes `read` and `write` |
| Resource server `mcp-server` | secret `mcp-server-secret`; tools `get_customer`, `list_customers`, `delete_customer` of type `Tool`, scope `call` |

> [!WARNING]
> These credentials are fixed demo values. Use them only in a local environment.

| File | Purpose |
|------|---------|
| [`docker-compose.yml`](docker-compose.yml) | Keycloak with the provider, and a container that configures the realm once |
| [`keycloak/bootstrap.sh`](keycloak/bootstrap.sh) | Creates the realm, users, agent, resource servers, schemas, policies and permissions |
| [`policies/`](policies) | Schemas and policies, one folder per resource server |
| [`cli-tests/tests-evaluate.sh`](cli-tests/tests-evaluate.sh) | The AuthZEN checks of the use cases below |

Every request is sent by the PEP with the access token of the resource server: `documents-api` for use
cases 1 to 3, `mcp-server` for use case 4.

## Use Case 1: Users by Role

**Scenario:** grant access to documents with Keycloak roles. The policy refers to the realm roles
`document-reader` and `document-writer`, and Keycloak resolves the user's effective roles (direct,
composite and inherited from groups).

**What it shows:** the subject's roles always come from Keycloak. A caller that claims a role in the
request gains nothing.

Policy [`policies/documents-api/documents.cedar`](policies/documents-api/documents.cedar):

```cedar
@id("document-readers-read")
permit (
  principal in Keycloak::Role::"document-reader",
  action == Documents::Action::"read",
  resource is Documents::Document
);

@id("document-writers-write")
permit (
  principal in Keycloak::Role::"document-writer",
  action == Documents::Action::"write",
  resource is Documents::Document
);
```

Request:

```json
{
  "subject":  { "type": "user", "id": "alice" },
  "resource": { "type": "Document", "id": "document-1" },
  "action":   { "name": "read" }
}
```

| Subject | Action | Decision |
|---------|--------|----------|
| `alice` | `read` | `true` |
| `alice` | `write` | `false` |
| `bob` | `write` | `true` |
| `alice`, sending `"properties": { "roles": "document-writer" }` | `write` | `false`: roles come from Keycloak, not from the request |

## Use Case 2: Authentication Context

**Scenario:** require a strong login for a sensitive action. Editors may change a document only when they
logged in with a passkey; a password login is not enough.

**What it shows:** how the user logged in is known by the application, not by the Keycloak AuthZEN call.
The PEP passes these facts (`acr`, `amr`) in the AuthZEN `context`. The schema declares them, so Cedar
receives them with their types (`amr` as a set) and ignores any key the schema does not declare.

Policy [`policies/documents-api/document-write-passkey.cedar`](policies/documents-api/document-write-passkey.cedar):

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

Request:

```json
{
  "subject":  { "type": "user", "id": "carol" },
  "resource": { "type": "Document", "id": "document-1" },
  "action":   { "name": "write" },
  "context":  { "acr": "inherence", "amr": ["passkeys", "mfa"] }
}
```

| Subject | Context | Decision |
|---------|---------|----------|
| `carol` | `acr` `inherence`, `amr` `["passkeys", "mfa"]` | `true` |
| `carol` | `acr` `inherence`, `amr` `["pwd"]` | `false` |

## Use Case 3: AI Agent Reads Documents

**Scenario:** authorize an AI agent by its workload identity. The planner agent is registered in Keycloak as
a client whose `clientId` is its SPIFFE ID, and only that agent may read documents.

**What it shows:** an agent is a Cedar principal of type `Keycloak::Client`, so a policy can grant access to
one specific agent identity, separately from the users.

Policy [`policies/documents-api/planner-agent-read.cedar`](policies/documents-api/planner-agent-read.cedar):

```cedar
@id("planner-agent-read")
permit (
  principal is Keycloak::Client,
  action == Documents::Action::"read",
  resource is Documents::Document
)
when { principal.clientId == "spiffe://example.org/ns/agents/sa/planner-agent" };
```

Request (see [How an AI Agent Is Identified](#how-an-ai-agent-is-identified)):

```json
{
  "subject":  { "type": "user", "id": "<sub of the agent's access token>" },
  "resource": { "type": "Document", "id": "document-1" },
  "action":   { "name": "read" }
}
```

| Subject | Action | Decision |
|---------|--------|----------|
| planner agent | `read` | `true` |
| planner agent | `write` | `false` |

## Use Case 4: AI Agent Calls MCP Tools

**Scenario:** control which MCP tools an agent may call. An MCP gateway checks every `tools/call` with
Keycloak before forwarding it. Support agents may use the customer read tools when their token grants
`mcp:tools`, and no agent may ever delete a customer.

**What it shows:** each tool is a Keycloak resource of type `Tool`, named after the tool, with the scope
`call`, so policies name tools directly. A `forbid` blocks a dangerous tool even when another policy, such
as the one for tool admins, would allow it.

Policies [`policies/mcp-server/tools.cedar`](policies/mcp-server/tools.cedar):

```cedar
// Support agents may call the customer read tools, when their token grants mcp:tools.
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

// Tool admins may call every tool...
@id("tool-admins-call-all-tools")
permit (
  principal is Keycloak::Client,
  action == Mcp::Action::"call",
  resource is Mcp::Tool
)
when { principal.roles.contains("tool-admin") };

// ...except delete_customer, which no agent may call.
@id("no-agent-calls-delete-customer")
forbid (
  principal is Keycloak::Client,
  action == Mcp::Action::"call",
  resource == Mcp::Tool::"delete_customer"
);
```

The agent sends an MCP `tools/call` to the gateway:

```json
{ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
  "params": { "name": "get_customer", "arguments": { "id": "cust-12345" } } }
```

The gateway asks Keycloak:

```json
{
  "subject":  { "type": "user", "id": "<sub of the agent's access token>" },
  "resource": { "type": "Tool", "id": "get_customer" },
  "action":   { "name": "call" },
  "context":  { "scope": ["mcp:tools"] }
}
```

| Agent role | Tool | `scope` in context | Decision | Decided by |
|------------|------|--------------------|----------|------------|
| `support-agent` | `get_customer`, `list_customers` | `["mcp:tools"]` | `true` | `support-agents-call-customer-read-tools` |
| `support-agent` | `get_customer` | missing | `false` | no permit matches |
| `support-agent` | `delete_customer` | `["mcp:tools"]` | `false` | `no-agent-calls-delete-customer` |
| `tool-admin` | `list_customers` | any | `true` | `tool-admins-call-all-tools` (unit test only) |
| `tool-admin` | `delete_customer` | any | `false` | `no-agent-calls-delete-customer` overrides the permit (unit test only) |

Notes on writing tool policies:

- One tool goes in the policy scope (`resource == Mcp::Tool::"delete_customer"`); a list of tools goes in
  the condition (`resource in [...]`). Cedar does not accept a list in the policy scope.
- To group tools without listing them, give the Keycloak resources an attribute such as `category` and test
  it as a tag: `resource.getTag("category").contains("customer")`.

## How an AI Agent Is Identified

An AI agent is a Keycloak client. It authenticates with client credentials and gets an access token.

1. The agent calls the PEP with its access token.
2. The PEP verifies the token and reads its `sub`. For a client credentials token, the `sub` is the
   agent's **service account user**.
3. The PEP sends that `sub` as the subject: `{ "type": "user", "id": "<sub>" }`.
4. The provider sees a service account user and uses its client as the principal: `Keycloak::Client`, with
   the agent's `clientId` and the roles of its service account.

Why not `{ "type": "client", "id": "<clientId>" }`? Keycloak's AuthZEN endpoint accepts a subject of type
`client` only when it is the caller itself. A gateway asking about an agent is a different client, so
Keycloak answers `false` without evaluating any policy.
