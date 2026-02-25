import path from 'node:path';
import { promises as fs } from 'node:fs';
import * as esbuild from 'esbuild';

const rootDir = process.cwd();
const manifestPath = path.join(rootDir, 'manifest.json');
const vaultPath = process.env.OBSIDIAN_VAULT_PATH;

if (!vaultPath) {
  console.error('Missing OBSIDIAN_VAULT_PATH.');
  console.error('Example: OBSIDIAN_VAULT_PATH="$HOME/Documents/MyVault" npm run dev:sync');
  process.exit(1);
}

const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
const pluginId = manifest.id;
if (!pluginId) {
  console.error('manifest.json is missing "id".');
  process.exit(1);
}

const pluginDir = path.join(vaultPath, '.obsidian', 'plugins', pluginId);

const syncFiles = async () => {
  await fs.mkdir(pluginDir, { recursive: true });

  const files = ['manifest.json', 'main.js', 'versions.json'];
  for (const optional of ['styles.css']) {
    try {
      await fs.access(path.join(rootDir, optional));
      files.push(optional);
    } catch {
      // optional asset missing
    }
  }

  for (const name of files) {
    await fs.copyFile(path.join(rootDir, name), path.join(pluginDir, name));
  }

  console.log(`[dev:sync] Synced ${files.join(', ')} to ${pluginDir}`);
};

const syncPlugin = {
  name: 'dev-sync-plugin',
  setup(build) {
    build.onEnd(async (result) => {
      if (result.errors.length > 0) {
        console.error('[dev:sync] Build failed; skipping sync');
        return;
      }

      try {
        await syncFiles();
      } catch (error) {
        console.error(`[dev:sync] Sync failed: ${error.message}`);
      }
    });
  }
};

const ctx = await esbuild.context({
  entryPoints: ['src/main.js'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  external: ['obsidian', 'electron'],
  outfile: 'main.js',
  logLevel: 'info',
  sourcemap: false,
  plugins: [syncPlugin]
});

await ctx.rebuild();
await ctx.watch();

console.log('[dev:sync] Watching src/main.js and syncing to your vault plugin folder...');

const shutdown = async () => {
  await ctx.dispose();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
