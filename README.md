# MCP-Util

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

## Community plugin release files

Each GitHub release must include:

- `manifest.json`
- `main.js`
- `styles.css` (only if your plugin uses one)

## Development workflow (Node.js)

Source lives in `src/main.js`. Build output is root `main.js` (the file Obsidian loads).

1. Install dev dependencies:
- `npm install`

2. One-time build:
- `npm run build`

3. Watch + auto-sync into your vault plugin folder:
- `OBSIDIAN_VAULT_PATH=\"/absolute/path/to/your/vault\" npm run dev:sync`

This will:
- rebuild `main.js` on every change to `src/main.js`
- copy `manifest.json`, `main.js`, `versions.json` (and `styles.css` if present) to:
- `<Vault>/.obsidian/plugins/mcp-search-server/`

## Local install in Obsidian

1. Find your Obsidian vault's plugins directory:
- `<Vault>/.obsidian/plugins/`

2. Create a new plugin folder:
- `<Vault>/.obsidian/plugins/mcp-search-server/`

3. Copy these files into that folder:
- `manifest.json`
- `main.js`
- `versions.json`

4. In Obsidian:
- Settings -> Community plugins -> Reload plugins
- Enable `MCP-Util`

## Publish to Obsidian Community Plugins

1. Bump `version` in `manifest.json`.
2. Add/update version mapping in `versions.json`.
3. Create a GitHub release tag matching `manifest.json` version (for example, `0.1.1`).
4. Attach `manifest.json` and `main.js` as release assets.
5. Submit or update your entry in the Obsidian releases index:
   - https://github.com/obsidianmd/obsidian-releases

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
