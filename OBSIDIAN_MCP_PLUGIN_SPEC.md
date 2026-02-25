# Obsidian MCP Search Plugin

## 1. Purpose

Build an Obsidian desktop plugin that exposes a local MCP server so AI clients can securely search and optionally write to notes in an Obsidian vault.

The plugin must let end users configure path-level access controls for read/write and expose search across:

- Tags
- Document properties (frontmatter)
- Full text

The plugin must return clickable links that open matching notes directly in Obsidian on the same machine.

Access control must support independent allow/deny for reads and writes on a per-directory basis (vault-relative path prefixes).

## 2. Goals and Non-Goals

### 2.1 Goals

- Provide a production-ready Obsidian plugin with embedded MCP server.
- Enforce default-deny path access control with explicit per-directory read and write rules.
- Expose MCP tools for search, read, and optional write operations.
- Return Obsidian URI links for direct navigation.
- Keep setup simple for non-technical users.

### 2.2 Non-Goals

- Cloud hosting or remote vault access.
- Mobile support.
- Cross-vault search in v1.
- Rich semantic/vector search in v1 (optional future enhancement).

## 3. Target Environment

- Obsidian desktop only (macOS first; cross-platform desktop later if needed).
- Plugin marked desktop-only.
- Local MCP access only (localhost).
- Node/Electron APIs allowed only where needed.

## 4. High-Level Architecture

### 4.1 Components

1. Plugin Runtime
- Obsidian plugin entrypoint (`onload`, `onunload`).
- Loads settings and starts/stops MCP server.

2. Settings and Persistence
- Obsidian settings tab for ACL, server mode, auth token, and index behavior.
- Persist settings via `loadData` / `saveData`.

3. Policy Engine (Security Boundary)
- Canonicalize and validate all paths.
- Enforce read/write allow/deny policy.
- Block traversal and symlink escapes.

4. Vault Access Layer
- Wrapper over `Vault`, `TFile`, and `MetadataCache`.
- Read/write/list operations with policy checks.

5. Search Service
- Tag search from metadata cache.
- Property search from frontmatter.
- Full-text index with incremental updates from vault events.

6. MCP Transport/Protocol Adapter
- MCP server implementation and tool registration.
- Input validation, output schema, and error mapping.

7. Link Builder
- Generates `obsidian://open?vault=<vault>&file=<encoded path>` links.

8. Audit and Diagnostics
- Structured logs for operation, caller, target path, allow/deny, and timing.

### 4.2 Data Flow

1. AI client calls MCP tool.
2. MCP adapter validates request schema.
3. Policy engine authorizes operation and path scope.
4. Vault/Search layer executes request.
5. Result formatter adds snippets, metadata, and Obsidian URI links.
6. MCP adapter returns result or typed error.

## 5. Security and Permissions

### 5.1 Trust Model

- Default deny for read and write.
- User explicitly grants allowed path prefixes.
- Read and write are evaluated independently per directory.
- Deny rules override allow rules for the same operation type.
- A path can be read-allowed and write-denied (or the inverse) by design.

### 5.2 ACL Model

Each rule should support:

- `path`: vault-relative path prefix
- `read_allow`: boolean
- `read_deny`: boolean
- `write_allow`: boolean
- `write_deny`: boolean

Recommended internal representation:

```ts
type AclRule = {
  path: string;       // vault-relative, normalized
  readAllow?: boolean;
  readDeny?: boolean;
  writeAllow?: boolean;
  writeDeny?: boolean;
};
```

Rule evaluation requirements:

- Evaluate read and write decisions separately.
- Use longest-prefix match first for directory specificity.
- Apply explicit deny precedence over allow for the same operation.
- If no matching allow is found for an operation, deny by default.

Example outcomes:

- `Projects/` read allow + write deny: AI may search/read notes under `Projects/` but cannot modify them.
- `Scratch/` write allow + read deny: AI may write to known target paths in `Scratch/` but cannot read existing note content.
- `Private/` read deny + write deny: no access regardless of broader parent allows.

### 5.3 Path Validation Rules

- Normalize separators and resolve `.`/`..`.
- Disallow absolute paths in tool inputs (require vault-relative).
- Resolve canonical path and verify it remains under vault root.
- Deny symlink traversal outside vault root.
- Deny binary/system files unless explicitly supported.

### 5.4 Authentication and Exposure

- Bind server to `127.0.0.1` only.
- Require bearer token for all MCP requests (except optional health endpoint).
- Support token rotation in settings.
- Never expose server on LAN in v1.

### 5.5 Write Safety

- `write` operations are disabled by default.
- Optional confirmation mode:
  - `off`: allow writes per ACL only
  - `dry-run`: return proposed patch but do not write
  - `confirm`: require user approval in Obsidian modal per request

## 6. MCP API Specification (v1)

### 6.1 Tool: `search_notes`

Search by tags, properties, full text, or hybrid.

Input schema:

```json
{
  "mode": "tags | properties | full_text | hybrid",
  "query": "string",
  "tags": ["optional", "tag", "array"],
  "properties": {
    "key": "value-or-filter"
  },
  "path_scope": ["optional/path/prefix"],
  "limit": 20,
  "offset": 0,
  "sort": "relevance | modified_desc | path_asc"
}
```

Output schema:

```json
{
  "total": 42,
  "items": [
    {
      "path": "Projects/Foo.md",
      "title": "Foo",
      "score": 0.91,
      "snippet": "matching excerpt...",
      "tags": ["#project"],
      "properties": { "status": "active" },
      "modified_time": "2026-02-24T12:34:56.000Z",
      "obsidian_url": "obsidian://open?vault=MyVault&file=Projects%2FFoo.md"
    }
  ]
}
```

Authorization:

- Requires read permission for every result path.

### 6.2 Tool: `read_note`

Read a specific note.

Input:

```json
{
  "path": "vault/relative/path.md",
  "include_metadata": true
}
```

Output:

```json
{
  "path": "vault/relative/path.md",
  "content": "...",
  "metadata": {
    "tags": ["#x"],
    "properties": { "k": "v" }
  },
  "obsidian_url": "obsidian://open?vault=MyVault&file=vault%2Frelative%2Fpath.md"
}
```

Authorization:

- Requires read permission on requested path.

### 6.3 Tool: `write_note` (optional in v1, recommended)

Create or replace content for a note.

Input:

```json
{
  "path": "vault/relative/path.md",
  "content": "...",
  "mode": "create | overwrite | append"
}
```

Output:

```json
{
  "path": "vault/relative/path.md",
  "written": true,
  "bytes": 1234,
  "obsidian_url": "obsidian://open?vault=MyVault&file=vault%2Frelative%2Fpath.md"
}
```

Authorization:

- Requires write permission on requested path.

### 6.4 Optional Tools

- `list_tags`
- `list_properties`
- `health_check`

### 6.5 Standard Error Model

Use machine-readable errors:

- `invalid_request`
- `unauthorized`
- `permission_denied`
- `path_not_allowed`
- `not_found`
- `conflict`
- `internal_error`

Error payload:

```json
{
  "code": "permission_denied",
  "message": "Write not allowed for path",
  "details": {
    "path": "Restricted/Secret.md"
  }
}
```

## 7. Search Implementation Details

### 7.1 Tag Search

- Pull from `MetadataCache` tags.
- Normalize tags to a canonical format (leading `#`, case strategy).
- Support AND/OR semantics (configurable).

### 7.2 Property Search

- Pull from frontmatter via metadata cache.
- Must support exact-equality comparison (`==`) in v1.
- Equality matching should work for string, number, and boolean property values.
- Optional operators (`contains`, `gt`, `lt`) for numeric/date in v1.1.

### 7.3 Full-Text Search

- Build local inverted index over Markdown files in allowed read scope.
- Tokenization:
  - Lowercase
  - Strip punctuation
  - Optional stemming (future)
- Ranking:
  - Basic TF-IDF/BM25-style scoring acceptable.
- Snippets:
  - Return short context windows around best match terms.

### 7.4 Incremental Index Updates

Subscribe to vault events:

- create
- modify
- delete
- rename

On event:

- Re-index only affected file.
- Maintain index consistency after rename/move.
- Fallback to scheduled full rebuild (optional).

### 7.5 Index Persistence

Options:

- In-memory only (simple, rebuild on startup).
- Disk-backed cache in plugin data directory (faster startup).

v1 recommendation:

- Start in-memory with startup progress indicator.
- Add disk cache in v1.1 if startup latency is high.

## 8. Obsidian URI and Clickable Links

### 8.1 Link Format

- `obsidian://open?vault=<vaultName>&file=<urlEncodedVaultRelativePath>`

### 8.2 Behavior Requirements

- URLs must be returned in every file-based result payload.
- Encode vault and file path safely.
- If file path is unavailable (rare), omit URL and include reason.

### 8.3 UX Requirement

- Links should render as clickable Markdown where client supports it.
- Include both human-readable title and URL in structured fields.

## 9. Plugin UX Requirements

### 9.1 Settings UI

Required settings:

- Server enabled toggle
- Host (fixed `127.0.0.1` by default)
- Port
- Auth token generate/regenerate
- ACL rule table:
  - path prefix
  - read allow toggle
  - read deny toggle
  - write allow toggle
  - write deny toggle
- Write mode (`off`, `dry-run`, `confirm`)
- Index memory budget (MB) cap
- Reindex action button
- Diagnostics/log level

### 9.2 Status Indicators

- Server status: stopped/starting/running/error
- Index status: idle/indexing/error + doc count + last indexed timestamp
- Index memory usage: current estimated MB used, budget cap MB, and percentage used

### 9.3 Safe Defaults

- Server disabled by default until user enables.
- No ACL allow rules preconfigured.
- Writes disabled by default.

## 10. Installation and End-User Setup

End user steps:

1. Install plugin from Community Plugins or manual install.
2. Enable plugin in Obsidian.
3. Open plugin settings:
- Generate auth token.
- Add read/write ACL path rules.
- Enable server.
4. Add MCP server config to AI client:
- transport endpoint (localhost + configured port)
- auth token
5. Test with `health_check` and `search_notes`.

## 11. Observability and Logging

- Structured logs with level (`error`, `warn`, `info`, `debug`).
- Log per MCP call:
  - tool name
  - caller/session id if available
  - decision (allow/deny)
  - target path or query
  - duration
- Redact secrets/tokens from logs.
- Optional rotating log file in plugin data folder.

## 12. Performance Targets (v1)

- Startup to server-ready: under 2s excluding initial indexing.
- Incremental index update on single file modify: under 300ms for typical notes.
- Search latency (`limit <= 20`): under 250ms on 10k-note vault (warm cache).

## 12.1 Index Memory Budget and Eviction

- The full-text index must maintain an estimated in-memory byte size.
- The plugin must expose this estimate in settings/status UI.
- A configurable memory cap (MB) should limit index growth.
- When above cap, evict least valuable entries first while preserving recent notes:
  - Prefer keeping recently modified or recently queried notes.
  - Prefer evicting oldest/least-recently-used note index shards first.
- Metadata-based search (tags/properties via `MetadataCache`) remains available even if full-text entries are evicted.
- Evicted notes can be lazily re-indexed on next access or periodic background pass.

## 13. Reliability Requirements

- Server must stop cleanly on plugin unload.
- No vault data corruption on failed writes.
- If indexing fails, search should return controlled error and allow retry.
- Plugin should recover from port-in-use with clear UI error and editable port.

## 14. Testing Requirements

### 14.1 Unit Tests

- ACL resolution and precedence.
- Path normalization and traversal blocking.
- Query parsing and validation.
- URI builder.

### 14.2 Integration Tests

- MCP tool call -> policy enforcement -> vault/search response path.
- Tag/property/full-text correctness on fixture vault.
- Write mode behavior (`off`, `dry-run`, `confirm`).

### 14.3 End-to-End Manual Tests

- Install + configure in clean Obsidian profile.
- Connect from one MCP client.
- Verify clickable links open exact note in Obsidian.
- Validate deny rules block both read and write.

## 15. Project Structure (Suggested)

```text
src/
  main.ts
  settings/
    settings.types.ts
    settings.tab.ts
  security/
    policy-engine.ts
    path-guard.ts
  vault/
    vault-service.ts
    metadata-service.ts
  search/
    search-service.ts
    tag-search.ts
    property-search.ts
    fulltext-index.ts
  mcp/
    server.ts
    tools/
      search-notes.ts
      read-note.ts
      write-note.ts
    schemas.ts
    errors.ts
  links/
    obsidian-uri.ts
  logging/
    logger.ts
tests/
```

## 16. Delivery Plan

### Phase 1: MVP

- Plugin scaffold with settings and local MCP server lifecycle.
- ACL enforcement for read operations.
- `search_notes` (tag + property + basic full text).
- `read_note`.
- Obsidian URI link generation.

### Phase 2: Safe Write Support

- `write_note` with write ACL and write mode controls.
- Audit logging improvements.

### Phase 3: Hardening

- Better ranking and snippet quality.
- Disk-backed index cache.
- Broader test coverage and performance tuning.

## 17. Acceptance Criteria

The implementation is acceptable when:

1. User can install and enable the plugin on desktop Obsidian.
2. User can configure path-based read/write permissions with default deny.
3. MCP client can call `search_notes` and receive correct results across tags, properties, and full text.
4. MCP client can call `read_note` only on allowed paths.
5. If `write_note` is enabled, writes are blocked unless write permission is granted.
6. Every returned note includes a valid `obsidian://open` URL that opens correctly on the same machine.
7. Errors are structured and actionable.
8. Plugin unload leaves no hanging server process.

## 18. Open Decisions (To Finalize Before Implementation)

- MCP transport choice (stdio bridge vs HTTP/SSE local endpoint).
- Token auth format and rotation UX.
- Whether to include write support in initial release.
- Exact full-text engine/library and ranking strategy.
- Whether property filtering supports advanced operators in v1.
