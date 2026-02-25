# Obsidian MCP Search Plugin (Local)

This plugin embeds a local MCP-compatible HTTP server inside Obsidian Desktop and exposes tools for:

- tag search
- property (frontmatter) search with exact equality
- full-text search
- secure note read/write (with per-directory ACL)
- clickable `obsidian://open` links

## Files in this plugin

- `manifest.json`
- `main.js`
- `versions.json`

## Local install in Obsidian

1. Find your Obsidian vault's plugins directory:
- `<Vault>/.obsidian/plugins/`

2. Create a new plugin folder:
- `<Vault>/.obsidian/plugins/obsidian-mcp-search/`

3. Copy these files into that folder:
- `manifest.json`
- `main.js`
- `versions.json`

4. In Obsidian:
- Settings -> Community plugins -> Reload plugins
- Enable `Obsidian MCP Search`

## First-time setup

1. Open plugin settings.
2. Generate/set auth token.
3. Add ACL rules (default deny until you add allows).
4. Enable server.
5. Optional: set write mode (`off`, `dry-run`, `confirm`).
6. Optional: set index memory cap.

## MCP endpoint

- URL: `http://127.0.0.1:27124/mcp` (or your configured host/port)
- Auth: `Authorization: Bearer <token>`

## Supported JSON-RPC methods

- `initialize`
- `tools/list`
- `tools/call`

Tool names:

- `search_notes`
- `read_note`
- `write_note`
- `list_tags`
- `list_properties`
- `health_check`

## Example call

```bash
curl -s http://127.0.0.1:27124/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "search_notes",
      "arguments": {
        "mode": "full_text",
        "query": "roadmap",
        "limit": 10
      }
    }
  }'
```

## Security defaults

- server disabled by default
- token required for all routes except `/health`
- ACL default deny for both read and write
- writes blocked unless write mode is not `off` and ACL permits write
