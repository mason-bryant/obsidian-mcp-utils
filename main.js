const { Plugin, PluginSettingTab, Setting, Modal, Notice } = require('obsidian');
const http = require('http');
const crypto = require('crypto');
const path = require('path');

const DEFAULT_SETTINGS = {
  serverEnabled: false,
  host: '127.0.0.1',
  port: 27124,
  authToken: '',
  writeMode: 'off', // off | dry-run | confirm
  indexMemoryCapMb: 64,
  aclRules: []
};

function generateToken() {
  return crypto.randomBytes(24).toString('hex');
}

function normalizeVaultPath(p) {
  if (!p) return '';
  const normalized = path.posix
    .normalize(String(p).replace(/\\/g, '/').trim())
    .replace(/^\/+/, '');
  if (normalized === '.' || normalized === '') return '';
  return normalized;
}

function pathMatchesPrefix(rulePrefix, targetPath) {
  if (!rulePrefix) return true;
  return targetPath === rulePrefix || targetPath.startsWith(`${rulePrefix}/`);
}

function tokenize(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[^a-z0-9_\-\s]/g, ' ')
    .split(/\s+/)
    .filter(Boolean);
}

function estimateDocBytes(content, tokenCount, uniqueTokenCount) {
  const contentBytes = Buffer.byteLength(content || '', 'utf8');
  const tokenBytes = tokenCount * 8;
  const uniqueBytes = uniqueTokenCount * 24;
  return contentBytes + tokenBytes + uniqueBytes;
}

class ConfirmWriteModal extends Modal {
  constructor(app, filePath, byteCount) {
    super(app);
    this.filePath = filePath;
    this.byteCount = byteCount;
    this.resolvePromise = null;
    this.result = false;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h3', { text: 'Confirm MCP write request' });
    contentEl.createEl('p', {
      text: `Allow writing to ${this.filePath} (${this.byteCount} bytes)?`
    });

    const buttonRow = contentEl.createDiv({ cls: 'mcp-write-confirm-row' });
    const allowBtn = buttonRow.createEl('button', { text: 'Allow' });
    const denyBtn = buttonRow.createEl('button', { text: 'Deny' });

    allowBtn.addEventListener('click', () => {
      this.result = true;
      this.close();
    });

    denyBtn.addEventListener('click', () => {
      this.result = false;
      this.close();
    });
  }

  onClose() {
    const { contentEl } = this;
    contentEl.empty();
    if (this.resolvePromise) {
      this.resolvePromise(this.result);
    }
  }

  waitForDecision() {
    return new Promise((resolve) => {
      this.resolvePromise = resolve;
      this.open();
    });
  }
}

class AclPolicyEngine {
  constructor(getRules) {
    this.getRules = getRules;
  }

  evaluate(pathInput, operation) {
    const normalizedPath = normalizeVaultPath(pathInput);
    const rules = (this.getRules() || []).map((r) => ({
      ...r,
      path: normalizeVaultPath(r.path)
    }));

    const allowKey = operation === 'read' ? 'readAllow' : 'writeAllow';
    const denyKey = operation === 'read' ? 'readDeny' : 'writeDeny';

    const matching = rules
      .filter((rule) => pathMatchesPrefix(rule.path, normalizedPath))
      .sort((a, b) => b.path.length - a.path.length);

    if (!matching.length) {
      return {
        allowed: false,
        reason: 'no_matching_rules',
        path: normalizedPath
      };
    }

    const levels = [...new Set(matching.map((r) => r.path.length))].sort((a, b) => b - a);

    for (const level of levels) {
      const group = matching.filter((r) => r.path.length === level);
      if (group.some((r) => !!r[denyKey])) {
        return {
          allowed: false,
          reason: 'explicit_deny',
          path: normalizedPath
        };
      }
      if (group.some((r) => !!r[allowKey])) {
        return {
          allowed: true,
          reason: 'explicit_allow',
          path: normalizedPath
        };
      }
    }

    return {
      allowed: false,
      reason: 'default_deny',
      path: normalizedPath
    };
  }

  assertAllowed(pathInput, operation) {
    const result = this.evaluate(pathInput, operation);
    if (!result.allowed) {
      const err = new Error(`${operation} not allowed for path: ${result.path}`);
      err.code = 'permission_denied';
      err.details = result;
      throw err;
    }
  }
}

class SearchIndex {
  constructor(app, policy, getMemoryCapBytes, log) {
    this.app = app;
    this.policy = policy;
    this.getMemoryCapBytes = getMemoryCapBytes;
    this.log = log;
    this.docs = new Map();
    this.inverted = new Map();
    this.totalBytes = 0;
    this.evictedCount = 0;
  }

  getStats() {
    const cap = this.getMemoryCapBytes();
    return {
      documentCount: this.docs.size,
      totalBytes: this.totalBytes,
      capBytes: cap,
      usagePercent: cap > 0 ? Math.min(100, (this.totalBytes / cap) * 100) : 0,
      evictedCount: this.evictedCount
    };
  }

  async rebuild() {
    this.docs.clear();
    this.inverted.clear();
    this.totalBytes = 0;
    this.evictedCount = 0;

    const files = this.app.vault.getMarkdownFiles();
    for (const file of files) {
      const vaultPath = normalizeVaultPath(file.path);
      if (!this.policy.evaluate(vaultPath, 'read').allowed) continue;
      const content = await this.app.vault.cachedRead(file);
      this.indexFile(file, content);
    }
    this.enforceCap();
  }

  removeFile(vaultPath) {
    const normalized = normalizeVaultPath(vaultPath);
    const existing = this.docs.get(normalized);
    if (!existing) return;

    for (const term of existing.terms.keys()) {
      const posting = this.inverted.get(term);
      if (!posting) continue;
      posting.delete(normalized);
      if (!posting.size) this.inverted.delete(term);
    }

    this.totalBytes -= existing.bytes;
    this.docs.delete(normalized);
  }

  indexFile(file, content) {
    const vaultPath = normalizeVaultPath(file.path);
    if (!this.policy.evaluate(vaultPath, 'read').allowed) {
      this.removeFile(vaultPath);
      return;
    }

    this.removeFile(vaultPath);

    const tokens = tokenize(content);
    const termFreq = new Map();
    for (const token of tokens) {
      termFreq.set(token, (termFreq.get(token) || 0) + 1);
    }

    const metadata = this.app.metadataCache.getFileCache(file) || {};
    const tags = (metadata.tags || []).map((t) => t.tag);
    const frontmatter = metadata.frontmatter || {};

    const doc = {
      path: vaultPath,
      title: file.basename,
      terms: termFreq,
      tokenCount: tokens.length,
      tags,
      frontmatter,
      bytes: estimateDocBytes(content, tokens.length, termFreq.size),
      modifiedTime: file.stat?.mtime || Date.now(),
      lastAccessTime: Date.now()
    };

    this.docs.set(vaultPath, doc);
    this.totalBytes += doc.bytes;

    for (const [term, freq] of termFreq.entries()) {
      let posting = this.inverted.get(term);
      if (!posting) {
        posting = new Map();
        this.inverted.set(term, posting);
      }
      posting.set(vaultPath, freq);
    }

    this.enforceCap();
  }

  touch(pathValue) {
    const doc = this.docs.get(normalizeVaultPath(pathValue));
    if (doc) doc.lastAccessTime = Date.now();
  }

  enforceCap() {
    const cap = this.getMemoryCapBytes();
    if (!cap || cap <= 0) return;

    if (this.totalBytes <= cap) return;

    const candidates = [...this.docs.values()].sort((a, b) => {
      const aFresh = Math.max(a.modifiedTime || 0, a.lastAccessTime || 0);
      const bFresh = Math.max(b.modifiedTime || 0, b.lastAccessTime || 0);
      return aFresh - bFresh;
    });

    for (const doc of candidates) {
      if (this.totalBytes <= cap) break;
      this.removeFile(doc.path);
      this.evictedCount += 1;
      this.log('info', 'index_eviction', {
        path: doc.path,
        bytes: doc.bytes,
        totalBytes: this.totalBytes,
        capBytes: cap
      });
    }
  }

  fullTextSearch(query, limit = 20, offset = 0) {
    const terms = tokenize(query);
    if (!terms.length) return { total: 0, hits: [] };

    const scoreMap = new Map();
    for (const term of terms) {
      const posting = this.inverted.get(term);
      if (!posting) continue;
      const idf = Math.log(1 + this.docs.size / (1 + posting.size));
      for (const [docPath, freq] of posting.entries()) {
        scoreMap.set(docPath, (scoreMap.get(docPath) || 0) + freq * idf);
      }
    }

    const sorted = [...scoreMap.entries()]
      .map(([docPath, score]) => ({ docPath, score }))
      .sort((a, b) => b.score - a.score);

    const paged = sorted.slice(offset, offset + limit);
    const hits = paged
      .map((entry) => {
        const doc = this.docs.get(entry.docPath);
        if (!doc) return null;
        doc.lastAccessTime = Date.now();
        return {
          path: doc.path,
          title: doc.title,
          score: Number(entry.score.toFixed(4)),
          tags: doc.tags,
          properties: doc.frontmatter,
          modified_time: new Date(doc.modifiedTime).toISOString()
        };
      })
      .filter(Boolean);

    return { total: sorted.length, hits };
  }
}

class ObsidianMcpPlugin extends Plugin {
  async onload() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    if (!this.settings.authToken) {
      this.settings.authToken = generateToken();
      await this.saveSettings();
    }

    this.policy = new AclPolicyEngine(() => this.settings.aclRules);
    this.searchIndex = new SearchIndex(
      this.app,
      this.policy,
      () => Math.max(1, Number(this.settings.indexMemoryCapMb || 64)) * 1024 * 1024,
      (level, event, data) => this.log(level, event, data)
    );

    this.registerVaultEvents();

    this.addCommand({
      id: 'mcp-reindex',
      name: 'Rebuild MCP full-text index',
      callback: async () => {
        await this.rebuildIndex();
      }
    });

    this.addSettingTab(new ObsidianMcpSettingTab(this.app, this));

    await this.rebuildIndex();

    if (this.settings.serverEnabled) {
      try {
        await this.startServer();
      } catch (error) {
        this.log('error', 'server_start_failed_onload', { message: error.message });
        new Notice(`MCP server failed to start: ${error.message}`);
      }
    }

    this.log('info', 'plugin_loaded', { version: this.manifest.version });
  }

  async onunload() {
    await this.stopServer();
    this.log('info', 'plugin_unloaded', {});
  }

  log(level, event, data) {
    const payload = {
      level,
      event,
      ts: new Date().toISOString(),
      ...data
    };

    if (payload.token) payload.token = '[REDACTED]';
    console.log('[obsidian-mcp-search]', payload);
  }

  registerVaultEvents() {
    this.registerEvent(
      this.app.vault.on('modify', async (file) => {
        if (!file || file.extension !== 'md') return;
        const content = await this.app.vault.cachedRead(file);
        this.searchIndex.indexFile(file, content);
      })
    );

    this.registerEvent(
      this.app.vault.on('create', async (file) => {
        if (!file || file.extension !== 'md') return;
        const content = await this.app.vault.cachedRead(file);
        this.searchIndex.indexFile(file, content);
      })
    );

    this.registerEvent(
      this.app.vault.on('delete', (file) => {
        if (!file || file.extension !== 'md') return;
        this.searchIndex.removeFile(file.path);
      })
    );

    this.registerEvent(
      this.app.vault.on('rename', async (file, oldPath) => {
        this.searchIndex.removeFile(oldPath);
        if (!file || file.extension !== 'md') return;
        const content = await this.app.vault.cachedRead(file);
        this.searchIndex.indexFile(file, content);
      })
    );
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  async rebuildIndex() {
    try {
      this.indexStatus = 'indexing';
      await this.searchIndex.rebuild();
      this.lastIndexedAt = Date.now();
      this.indexStatus = 'idle';
      new Notice('MCP index rebuilt');
    } catch (error) {
      this.indexStatus = 'error';
      this.log('error', 'index_rebuild_failed', { message: error.message });
      new Notice(`MCP index rebuild failed: ${error.message}`);
    }
  }

  makeObsidianUrl(vaultPath) {
    return `obsidian://open?vault=${encodeURIComponent(this.app.vault.getName())}&file=${encodeURIComponent(normalizeVaultPath(vaultPath))}`;
  }

  validateVaultPath(inputPath) {
    const normalized = normalizeVaultPath(inputPath);
    if (!normalized || normalized.includes('..')) {
      const err = new Error('Invalid vault-relative path');
      err.code = 'invalid_request';
      throw err;
    }
    return normalized;
  }

  ensureAuthorized(req, res) {
    const header = req.headers.authorization || '';
    const expected = `Bearer ${this.settings.authToken}`;
    if (!this.settings.authToken || header !== expected) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { code: 'unauthorized', message: 'Invalid token' } }));
      return false;
    }
    return true;
  }

  async startServer() {
    if (this.server) return;

    const server = http.createServer(async (req, res) => {
      try {
        if (req.method === 'GET' && req.url === '/health') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true, status: this.indexStatus || 'idle' }));
          return;
        }

        if (!this.ensureAuthorized(req, res)) return;

        if (req.method === 'GET' && req.url === '/tools') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ tools: this.getTools() }));
          return;
        }

        if (req.method !== 'POST' || req.url !== '/mcp') {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: { code: 'not_found', message: 'Route not found' } }));
          return;
        }

        const body = await this.readRequestBody(req);
        const message = JSON.parse(body || '{}');
        const response = await this.handleJsonRpc(message);

        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(response));
      } catch (error) {
        this.log('error', 'server_request_error', { message: error.message });
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            error: {
              code: 'internal_error',
              message: error.message
            }
          })
        );
      }
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.settings.port, this.settings.host, () => {
        server.off('error', reject);
        resolve();
      });
    }).catch((error) => {
      try {
        server.close();
      } catch (_e) {
        // no-op
      }
      throw error;
    });

    this.server = server;
    new Notice(`MCP server running at http://${this.settings.host}:${this.settings.port}`);
    this.log('info', 'server_started', { host: this.settings.host, port: this.settings.port });
  }

  async stopServer() {
    if (!this.server) return;
    await new Promise((resolve) => this.server.close(resolve));
    this.server = null;
    this.log('info', 'server_stopped', {});
  }

  async restartServer() {
    await this.stopServer();
    if (this.settings.serverEnabled) {
      try {
        await this.startServer();
      } catch (error) {
        this.log('error', 'server_restart_failed', { message: error.message });
        new Notice(`MCP server restart failed: ${error.message}`);
      }
    }
  }

  readRequestBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  getTools() {
    return [
      {
        name: 'search_notes',
        description: 'Search notes by tags, properties, full text, or hybrid mode.',
        inputSchema: {
          type: 'object',
          properties: {
            mode: { type: 'string', enum: ['tags', 'properties', 'full_text', 'hybrid'] },
            query: { type: 'string' },
            tags: { type: 'array', items: { type: 'string' } },
            properties: { type: 'object' },
            path_scope: { type: 'array', items: { type: 'string' } },
            limit: { type: 'number' },
            offset: { type: 'number' },
            sort: { type: 'string' }
          }
        }
      },
      {
        name: 'read_note',
        description: 'Read a note by vault-relative path.',
        inputSchema: {
          type: 'object',
          required: ['path'],
          properties: {
            path: { type: 'string' },
            include_metadata: { type: 'boolean' }
          }
        }
      },
      {
        name: 'write_note',
        description: 'Write a note by vault-relative path (create/overwrite/append).',
        inputSchema: {
          type: 'object',
          required: ['path', 'content'],
          properties: {
            path: { type: 'string' },
            content: { type: 'string' },
            mode: { type: 'string', enum: ['create', 'overwrite', 'append'] }
          }
        }
      },
      {
        name: 'list_tags',
        description: 'List tags discovered in allowed notes.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'list_properties',
        description: 'List frontmatter property keys in allowed notes.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'health_check',
        description: 'Return server and index status.',
        inputSchema: { type: 'object', properties: {} }
      }
    ];
  }

  async handleJsonRpc(message) {
    const id = message.id ?? null;
    const method = message.method;
    const params = message.params || {};

    try {
      if (method === 'initialize') {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: '2025-03-26',
            serverInfo: {
              name: 'obsidian-mcp-search',
              version: this.manifest.version
            },
            capabilities: {
              tools: {}
            }
          }
        };
      }

      if (method === 'tools/list') {
        return {
          jsonrpc: '2.0',
          id,
          result: { tools: this.getTools() }
        };
      }

      if (method === 'tools/call') {
        const toolName = params.name;
        const args = params.arguments || {};
        const structured = await this.callTool(toolName, args);
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(structured, null, 2) }],
            structuredContent: structured
          }
        };
      }

      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32601,
          message: `Method not found: ${method}`
        }
      };
    } catch (error) {
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32000,
          message: error.message,
          data: {
            code: error.code || 'internal_error',
            details: error.details || null
          }
        }
      };
    }
  }

  async callTool(name, args) {
    const start = Date.now();
    let result;

    if (name === 'search_notes') {
      result = await this.toolSearchNotes(args);
    } else if (name === 'read_note') {
      result = await this.toolReadNote(args);
    } else if (name === 'write_note') {
      result = await this.toolWriteNote(args);
    } else if (name === 'list_tags') {
      result = await this.toolListTags();
    } else if (name === 'list_properties') {
      result = await this.toolListProperties();
    } else if (name === 'health_check') {
      result = {
        ok: true,
        server: {
          enabled: !!this.server,
          host: this.settings.host,
          port: this.settings.port
        },
        index: this.searchIndex.getStats()
      };
    } else {
      const err = new Error(`Unknown tool: ${name}`);
      err.code = 'invalid_request';
      throw err;
    }

    this.log('info', 'tool_call', {
      tool: name,
      durationMs: Date.now() - start
    });

    return result;
  }

  getAllowedFiles(pathScopes = []) {
    const normalizedScopes = (pathScopes || []).map((p) => normalizeVaultPath(p)).filter(Boolean);
    return this.app.vault.getMarkdownFiles().filter((file) => {
      const p = normalizeVaultPath(file.path);
      if (!this.policy.evaluate(p, 'read').allowed) return false;
      if (!normalizedScopes.length) return true;
      return normalizedScopes.some((scope) => pathMatchesPrefix(scope, p));
    });
  }

  async toolSearchNotes(args) {
    const mode = args.mode || 'hybrid';
    const limit = Number(args.limit || 20);
    const offset = Number(args.offset || 0);
    const sort = args.sort || 'relevance';
    const query = String(args.query || '');
    const tags = (args.tags || []).map((t) => (String(t).startsWith('#') ? String(t) : `#${String(t)}`));
    const properties = args.properties || {};
    const pathScope = args.path_scope || [];

    let results = [];

    if (mode === 'full_text' || mode === 'hybrid') {
      const fullText = this.searchIndex.fullTextSearch(query, Math.max(limit * 3, 50), 0).hits;
      results.push(...fullText.map((r) => ({ ...r, _source: 'full_text' })));
    }

    if (mode === 'tags' || mode === 'hybrid') {
      const files = this.getAllowedFiles(pathScope);
      for (const file of files) {
        const cache = this.app.metadataCache.getFileCache(file) || {};
        const fileTags = new Set((cache.tags || []).map((t) => t.tag));
        if (!tags.length || tags.every((tag) => fileTags.has(tag))) {
          results.push({
            path: normalizeVaultPath(file.path),
            title: file.basename,
            score: 0.5,
            tags: [...fileTags],
            properties: cache.frontmatter || {},
            modified_time: new Date(file.stat?.mtime || Date.now()).toISOString(),
            _source: 'tags'
          });
        }
      }
    }

    if (mode === 'properties' || mode === 'hybrid') {
      const files = this.getAllowedFiles(pathScope);
      for (const file of files) {
        const cache = this.app.metadataCache.getFileCache(file) || {};
        const fm = cache.frontmatter || {};
        const matches = Object.entries(properties).every(([k, expected]) => {
          const actual = fm[k];
          if (typeof expected === 'number' || typeof expected === 'boolean') return actual === expected;
          return String(actual ?? '') === String(expected);
        });
        if (matches || !Object.keys(properties).length) {
          results.push({
            path: normalizeVaultPath(file.path),
            title: file.basename,
            score: 0.4,
            tags: (cache.tags || []).map((t) => t.tag),
            properties: fm,
            modified_time: new Date(file.stat?.mtime || Date.now()).toISOString(),
            _source: 'properties'
          });
        }
      }
    }

    const byPath = new Map();
    for (const row of results) {
      if (pathScope.length) {
        const normalizedPath = normalizeVaultPath(row.path);
        if (!pathScope.some((scope) => pathMatchesPrefix(normalizeVaultPath(scope), normalizedPath))) {
          continue;
        }
      }
      if (!this.policy.evaluate(row.path, 'read').allowed) continue;

      const existing = byPath.get(row.path);
      if (!existing || row.score > existing.score) {
        byPath.set(row.path, row);
      } else {
        existing.score += row.score * 0.25;
      }
    }

    let merged = [...byPath.values()];

    if (query) {
      const lowered = query.toLowerCase();
      merged = merged.map((item) => {
        const titleBonus = item.title.toLowerCase().includes(lowered) ? 0.15 : 0;
        return { ...item, score: Number((item.score + titleBonus).toFixed(4)) };
      });
    }

    if (sort === 'modified_desc') {
      merged.sort((a, b) => String(b.modified_time).localeCompare(String(a.modified_time)));
    } else if (sort === 'path_asc') {
      merged.sort((a, b) => a.path.localeCompare(b.path));
    } else {
      merged.sort((a, b) => b.score - a.score);
    }

    const paged = merged.slice(offset, offset + limit).map((item) => {
      this.searchIndex.touch(item.path);
      return {
        ...item,
        snippet: query ? `Match for "${query}" in ${item.title}` : `Match in ${item.title}`,
        obsidian_url: this.makeObsidianUrl(item.path)
      };
    });

    return {
      total: merged.length,
      items: paged,
      memory: this.searchIndex.getStats()
    };
  }

  async toolReadNote(args) {
    const vaultPath = this.validateVaultPath(args.path);
    this.policy.assertAllowed(vaultPath, 'read');

    const file = this.app.vault.getAbstractFileByPath(vaultPath);
    if (!file || file.extension !== 'md') {
      const err = new Error('Note not found');
      err.code = 'not_found';
      throw err;
    }

    const content = await this.app.vault.cachedRead(file);
    const metadata = this.app.metadataCache.getFileCache(file) || {};

    this.searchIndex.touch(vaultPath);

    return {
      path: vaultPath,
      content,
      metadata: args.include_metadata === false
        ? undefined
        : {
            tags: (metadata.tags || []).map((t) => t.tag),
            properties: metadata.frontmatter || {}
          },
      obsidian_url: this.makeObsidianUrl(vaultPath)
    };
  }

  async toolWriteNote(args) {
    if (this.settings.writeMode === 'off') {
      const err = new Error('Writes are disabled by plugin settings');
      err.code = 'permission_denied';
      throw err;
    }

    const vaultPath = this.validateVaultPath(args.path);
    this.policy.assertAllowed(vaultPath, 'write');

    const content = String(args.content || '');
    const mode = args.mode || 'overwrite';

    const existing = this.app.vault.getAbstractFileByPath(vaultPath);

    if (this.settings.writeMode === 'confirm') {
      const modal = new ConfirmWriteModal(this.app, vaultPath, Buffer.byteLength(content, 'utf8'));
      const approved = await modal.waitForDecision();
      if (!approved) {
        const err = new Error('Write denied by user');
        err.code = 'permission_denied';
        throw err;
      }
    }

    if (this.settings.writeMode === 'dry-run') {
      return {
        path: vaultPath,
        written: false,
        dry_run: true,
        mode,
        bytes: Buffer.byteLength(content, 'utf8'),
        obsidian_url: this.makeObsidianUrl(vaultPath)
      };
    }

    if (mode === 'create') {
      if (existing) {
        const err = new Error('File already exists');
        err.code = 'conflict';
        throw err;
      }
      await this.app.vault.create(vaultPath, content);
    } else if (mode === 'append') {
      if (!existing || existing.extension !== 'md') {
        const err = new Error('Cannot append: note not found');
        err.code = 'not_found';
        throw err;
      }
      const current = await this.app.vault.cachedRead(existing);
      await this.app.vault.modify(existing, `${current}${current.endsWith('\n') ? '' : '\n'}${content}`);
    } else {
      if (!existing) {
        await this.app.vault.create(vaultPath, content);
      } else {
        await this.app.vault.modify(existing, content);
      }
    }

    const written = this.app.vault.getAbstractFileByPath(vaultPath);
    if (written && written.extension === 'md') {
      const updated = await this.app.vault.cachedRead(written);
      this.searchIndex.indexFile(written, updated);
    }

    return {
      path: vaultPath,
      written: true,
      dry_run: false,
      mode,
      bytes: Buffer.byteLength(content, 'utf8'),
      obsidian_url: this.makeObsidianUrl(vaultPath)
    };
  }

  async toolListTags() {
    const tags = new Set();
    for (const file of this.getAllowedFiles()) {
      const cache = this.app.metadataCache.getFileCache(file) || {};
      for (const tag of cache.tags || []) {
        tags.add(tag.tag);
      }
    }
    return { tags: [...tags].sort() };
  }

  async toolListProperties() {
    const keys = new Set();
    for (const file of this.getAllowedFiles()) {
      const cache = this.app.metadataCache.getFileCache(file) || {};
      const fm = cache.frontmatter || {};
      for (const key of Object.keys(fm)) {
        keys.add(key);
      }
    }
    return { properties: [...keys].sort() };
  }
}

class ObsidianMcpSettingTab extends PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  createAgentConfigBlock(containerEl, title, bodyText) {
    const section = containerEl.createDiv({ cls: 'mcp-agent-config-block' });
    section.createEl('h4', { text: title });

    new Setting(section)
      .setName('Copy')
      .setDesc('Copy this config block to clipboard.')
      .addButton((btn) =>
        btn.setButtonText('Copy').onClick(async () => {
          try {
            await navigator.clipboard.writeText(bodyText);
            new Notice(`${title} config copied`);
          } catch (error) {
            new Notice(`Copy failed: ${error.message}`);
          }
        })
      );

    section.createEl('pre', { text: bodyText });
  }

  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl('h2', { text: 'Obsidian MCP Search Settings' });

    new Setting(containerEl)
      .setName('Enable MCP server')
      .setDesc('Starts a local MCP-compatible HTTP server bound to localhost.')
      .addToggle((toggle) =>
        toggle.setValue(this.plugin.settings.serverEnabled).onChange(async (value) => {
          this.plugin.settings.serverEnabled = value;
          await this.plugin.saveSettings();
          await this.plugin.restartServer();
          this.display();
        })
      );

    new Setting(containerEl)
      .setName('Host')
      .setDesc('Local bind host. Keep 127.0.0.1 for safety.')
      .addText((text) =>
        text
          .setPlaceholder('127.0.0.1')
          .setValue(String(this.plugin.settings.host || '127.0.0.1'))
          .onChange(async (value) => {
            this.plugin.settings.host = value || '127.0.0.1';
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('Port')
      .setDesc('Local port for MCP server.')
      .addText((text) =>
        text
          .setPlaceholder('27124')
          .setValue(String(this.plugin.settings.port || 27124))
          .onChange(async (value) => {
            const parsed = Number(value);
            if (!Number.isFinite(parsed) || parsed <= 0) return;
            this.plugin.settings.port = parsed;
            await this.plugin.saveSettings();
          })
      )
      .addButton((btn) =>
        btn.setButtonText('Restart').onClick(async () => {
          await this.plugin.restartServer();
          new Notice('MCP server restarted');
        })
      );

    new Setting(containerEl)
      .setName('Auth token')
      .setDesc('Bearer token required for MCP requests.')
      .addText((text) =>
        text
          .setValue(this.plugin.settings.authToken)
          .onChange(async (value) => {
            this.plugin.settings.authToken = String(value || '').trim();
            await this.plugin.saveSettings();
          })
      )
      .addButton((btn) =>
        btn.setButtonText('Regenerate').onClick(async () => {
          this.plugin.settings.authToken = generateToken();
          await this.plugin.saveSettings();
          this.display();
          new Notice('Token regenerated');
        })
      );

    new Setting(containerEl)
      .setName('Write mode')
      .setDesc('off: block writes, dry-run: simulate only, confirm: prompt before write.')
      .addDropdown((dropdown) =>
        dropdown
          .addOption('off', 'off')
          .addOption('dry-run', 'dry-run')
          .addOption('confirm', 'confirm')
          .setValue(this.plugin.settings.writeMode)
          .onChange(async (value) => {
            this.plugin.settings.writeMode = value;
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName('Index memory cap (MB)')
      .setDesc('Max memory budget for full-text index. Older/colder entries are evicted first.')
      .addText((text) =>
        text
          .setPlaceholder('64')
          .setValue(String(this.plugin.settings.indexMemoryCapMb || 64))
          .onChange(async (value) => {
            const parsed = Number(value);
            if (!Number.isFinite(parsed) || parsed < 1) return;
            this.plugin.settings.indexMemoryCapMb = parsed;
            await this.plugin.saveSettings();
          })
      )
      .addButton((btn) =>
        btn.setButtonText('Apply cap now').onClick(async () => {
          this.plugin.searchIndex.enforceCap();
          this.display();
        })
      );

    const stats = this.plugin.searchIndex.getStats();
    new Setting(containerEl)
      .setName('Index memory usage')
      .setDesc(
        `${(stats.totalBytes / (1024 * 1024)).toFixed(2)} MB / ${(stats.capBytes / (1024 * 1024)).toFixed(2)} MB (${stats.usagePercent.toFixed(1)}%), docs: ${stats.documentCount}, evicted: ${stats.evictedCount}`
      )
      .addButton((btn) =>
        btn.setButtonText('Refresh').onClick(() => {
          this.display();
        })
      );

    new Setting(containerEl)
      .setName('Rebuild full-text index')
      .setDesc('Re-index all allowed markdown files.')
      .addButton((btn) =>
        btn.setButtonText('Rebuild').onClick(async () => {
          await this.plugin.rebuildIndex();
          this.display();
        })
      );

    containerEl.createEl('h3', { text: 'ACL Rules (per-directory allow/deny for read/write)' });
    containerEl.createEl('p', {
      text: 'Rules are evaluated by most specific path prefix first. Explicit deny wins over allow for each operation.'
    });

    const rules = this.plugin.settings.aclRules || [];
    rules.forEach((rule, index) => {
      new Setting(containerEl)
        .setName(`Rule ${index + 1}`)
        .setDesc('Most specific path prefix wins.')
        .addButton((btn) =>
          btn.setWarning().setButtonText('Delete').onClick(async () => {
            this.plugin.settings.aclRules.splice(index, 1);
            await this.plugin.saveSettings();
            this.display();
          })
        );

      new Setting(containerEl).setName('Path').addText((text) =>
        text
          .setPlaceholder('Projects/')
          .setValue(rule.path || '')
          .onChange(async (value) => {
            rule.path = normalizeVaultPath(value);
            await this.plugin.saveSettings();
          })
      );

      new Setting(containerEl).setName('Read allow').addToggle((toggle) =>
        toggle.setValue(!!rule.readAllow).onChange(async (value) => {
          rule.readAllow = value;
          await this.plugin.saveSettings();
        })
      );

      new Setting(containerEl).setName('Read deny').addToggle((toggle) =>
        toggle.setValue(!!rule.readDeny).onChange(async (value) => {
          rule.readDeny = value;
          await this.plugin.saveSettings();
        })
      );

      new Setting(containerEl).setName('Write allow').addToggle((toggle) =>
        toggle.setValue(!!rule.writeAllow).onChange(async (value) => {
          rule.writeAllow = value;
          await this.plugin.saveSettings();
        })
      );

      new Setting(containerEl).setName('Write deny').addToggle((toggle) =>
        toggle.setValue(!!rule.writeDeny).onChange(async (value) => {
          rule.writeDeny = value;
          await this.plugin.saveSettings();
        })
      );

      containerEl.createEl('hr');
    });

    new Setting(containerEl)
      .setName('Add ACL rule')
      .setDesc('Creates a new empty path rule.')
      .addButton((btn) =>
        btn.setButtonText('Add').onClick(async () => {
          this.plugin.settings.aclRules.push({
            path: '',
            readAllow: false,
            readDeny: false,
            writeAllow: false,
            writeDeny: false
          });
          await this.plugin.saveSettings();
          this.display();
        })
      );

    const mcpUrl = `http://${this.plugin.settings.host}:${this.plugin.settings.port}/mcp`;
    const authToken = this.plugin.settings.authToken || '';
    const cursorConfig = JSON.stringify(
      {
        mcpServers: {
          obsidian: {
            transport: 'http',
            url: mcpUrl,
            headers: {
              Authorization: `Bearer ${authToken}`
            }
          }
        }
      },
      null,
      2
    );

    const claudeConfig = JSON.stringify(
      {
        mcpServers: {
          obsidian: {
            type: 'http',
            url: mcpUrl,
            headers: {
              Authorization: `Bearer ${authToken}`
            }
          }
        }
      },
      null,
      2
    );

    const codexConfig = JSON.stringify(
      {
        mcp_servers: {
          obsidian: {
            transport: 'http',
            url: mcpUrl,
            headers: {
              Authorization: `Bearer ${authToken}`
            }
          }
        }
      },
      null,
      2
    );

    containerEl.createEl('h3', { text: 'Agent Configuration (Copy Ready)' });
    containerEl.createEl('p', {
      text: 'These blocks include the current server URL and token from this plugin settings page.'
    });

    this.createAgentConfigBlock(containerEl, 'Cursor', cursorConfig);
    this.createAgentConfigBlock(containerEl, 'Claud (Claude Desktop)', claudeConfig);
    this.createAgentConfigBlock(containerEl, 'Codex', codexConfig);

    containerEl.createEl('p', {
      text: `Server status: ${this.plugin.server ? 'running' : 'stopped'} | index status: ${this.plugin.indexStatus || 'idle'} | last indexed: ${this.plugin.lastIndexedAt ? new Date(this.plugin.lastIndexedAt).toLocaleString() : 'never'}`
    });
  }
}

module.exports = ObsidianMcpPlugin;
