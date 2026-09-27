# Remote MCP with single-user Auth0 OAuth

The HTTP server is designed so the Wanderlog session and MCP authentication are separate:

- `WANDERLOG_COOKIE` is a server-side credential used only when the server calls wanderlog.com.
- Auth0 access tokens authenticate MCP clients such as ChatGPT and Claude.
- `AUTH0_ALLOWED_SUB` restricts the resource server to one Auth0 user even if another user can obtain a token for the API.

## 1. Create the Auth0 API

In Auth0, create an API for this MCP server.

Set the **Identifier** to the exact public MCP URL, including `/mcp`, for example:

```text
https://wanderlog-mcp-dzlf.onrender.com/mcp
```

Use **RS256** signing and add an API permission/scope named:

```text
mcp
```

At the Auth0 tenant level:

1. Enable **Resource Parameter Compatibility Profile** so MCP's RFC 8707 `resource` parameter is accepted.
2. Enable **Dynamic Client Registration (DCR)** if the MCP client you use relies on DCR.

ChatGPT and other modern MCP clients use OAuth authorization-code + PKCE. Auth0 remains the authorization server; this project is only the protected resource server.

## 2. Identify your Auth0 user

Sign into Auth0 using the identity you want to permit, then open **User Management → Users** and copy the user's exact **User ID** / `sub`, for example:

```text
google-oauth2|123456789012345678901
```

That exact string becomes `AUTH0_ALLOWED_SUB`.

The server verifies this claim itself, so a valid Auth0 token belonging to any other account is rejected.

## 3. Configure the hosted server

Set these environment variables on Render, Fly.io, or your other host:

```text
WANDERLOG_COOKIE=s%3A...
AUTH0_ISSUER=https://YOUR_TENANT.us.auth0.com/
MCP_RESOURCE_URL=https://wanderlog-mcp-dzlf.onrender.com/mcp
AUTH0_ALLOWED_SUB=google-oauth2|123456789012345678901
```

Do not put any of these secret values in Git. `WANDERLOG_COOKIE` grants access to your Wanderlog account and should only exist in the hosting provider's secret/environment store.

`MCP_RESOURCE_URL` must exactly match the Auth0 API Identifier. A different scheme, host, path, or trailing slash changes the OAuth audience and tokens will be rejected.

## 4. OAuth discovery endpoints

The server exposes protected-resource metadata without authentication:

```text
GET /.well-known/oauth-protected-resource
GET /.well-known/oauth-protected-resource/mcp
```

An unauthenticated request to `/mcp` returns `401 Unauthorized` with a `WWW-Authenticate` challenge pointing clients to the metadata document.

All `POST`, `GET`, and `DELETE` requests to `/mcp` require an Auth0 bearer access token. The server checks:

- RS256 signature against Auth0's JWKS
- issuer (`AUTH0_ISSUER`)
- audience (`MCP_RESOURCE_URL`)
- expiration / not-before time
- `mcp` scope
- exact user subject (`AUTH0_ALLOWED_SUB`)

Only after those checks pass does the server use `WANDERLOG_COOKIE` to create the Wanderlog context.

`GET /health` remains public for hosting-platform health checks and contains no account information.

## 5. Connect an MCP client

Use the public MCP URL as the remote server URL:

```text
https://wanderlog-mcp-dzlf.onrender.com/mcp
```

The client should discover Auth0 from the protected-resource metadata and start the OAuth flow. Complete the login using the same Auth0 account whose user ID is configured in `AUTH0_ALLOWED_SUB`.

If another account completes Auth0 login, Auth0 may issue it a token, but the MCP server will still return `401` because the token's `sub` is not the allowed user.

## 6. Rotating credentials

### Wanderlog session

Replace `WANDERLOG_COOKIE` on the host and restart/redeploy the service. MCP clients do not need to be reconfigured.

### Auth0 access

To change which account is permitted, update `AUTH0_ALLOWED_SUB` and restart/redeploy.

To revoke an MCP client's authorization independently of Wanderlog, revoke its Auth0 authorization/session or remove its Auth0 client registration. The Wanderlog cookie never needs to be shared with the client.
