import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['src/main.js'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  external: ['obsidian', 'electron'],
  outfile: 'main.js',
  logLevel: 'info',
  sourcemap: false
});
