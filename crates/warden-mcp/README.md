# Warden MCP server

`aivory-warden mcp` runs a stdio MCP server. An agent can use your secrets through it. The agent never sees a secret value.

## Tools

| Tool | What it does |
|---|---|
| `list_secrets` | Names, provider, status, next rotation, allowed hosts. No values. |
| `http_request` | HTTPS request. The daemon adds the secret to one header and removes it from the answer. |
| `request_rotation` | Rotate a secret now. Limit: 1 per secret per hour. Some secrets need confirmation in the desktop app. |
| `get_policy` | Rotation policy and allowed hosts of a secret. |
| `set_policy` | Change the rotation policy. Needs the `mcp-admin` permission. Turning rotation off needs confirmation in the desktop app. |
| `save_secret` | Put a new secret (for example a token that the agent just created) into the inbox. The user accepts it. Needs the `inbox` permission: `awd pair <name> --cap mcp --cap inbox`. |

There is no `get_secret` tool. `run_with_secret` is off by default and needs an opt-in for each secret.

## Client setup

Pair the client first (`awd pair mcp`). Then add the server.

### Claude Code

```sh
claude mcp add aivory-warden -- aivory-warden mcp
```

### Claude Desktop

Add this to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aivory-warden": {
      "command": "aivory-warden",
      "args": ["mcp"]
    }
  }
}
```

### Cursor

Add this to `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project):

```json
{
  "mcpServers": {
    "aivory-warden": {
      "command": "aivory-warden",
      "args": ["mcp"]
    }
  }
}
```

The server writes only MCP frames to stdout. Set `WARDEN_LOG=debug` to get logs on stderr.

## What we promise

- No tool returns a secret value. There is no `get_secret`.
- `http_request` sends the secret only in the header that the vault defines for the secret.
- The request must use HTTPS on port 443 and go to a host in the allowlist of the secret.
- The proxy resolves the host, refuses private, loopback, link-local, CGNAT, multicast and unspecified addresses, and connects to the address that it checked.
- The proxy does not follow redirects.
- A request body is limited to 1 MiB, a response to 2 MiB, and the time to 30 s.
- The proxy removes the secret from the response body and headers. It also removes the base64, base64url, hex and URL-encoded forms.
- The URL, the query and the body must not contain the secret placeholder. A caller cannot set the secret header, `Authorization`, `Cookie` or `Proxy-Authorization`.
- A client with only the `mcp` permission cannot change a policy.

## What we do not promise

- Redaction is best effort. An API that transforms the secret in another way can still leak it.
- We do not protect against malware that runs as the same user.
- We do not protect against an agent that has shell access. It can read your files and the environment.
- We do not protect a secret after you write it to a sink (a file, an environment variable, an SSH host) and let the agent read that place.
- An allowed host can send the secret on to other parties. The allowlist is only as safe as the hosts in it.
