#!/usr/bin/env node
/**
 * Cross-platform verification for the admin console.
 *
 * Runs the TypeScript compiler in no-emit mode, then the production Vite build.
 * Both tools come from the local `node_modules/.bin` directory, so no global
 * install and no shell-specific syntax is required.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const isWindows = process.platform === 'win32';

function binary(name) {
  const file = isWindows ? `${name}.cmd` : name;
  return path.join(root, 'node_modules', '.bin', file);
}

function run(name, args) {
  const result = spawnSync(binary(name), args, {
    cwd: root,
    stdio: 'inherit',
    shell: isWindows,
  });

  if (result.error) {
    console.error(`failed to start ${name}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

run('tsc', ['--noEmit', '--pretty', 'false']);
run('vite', ['build']);

console.log('verify: typecheck and production build passed');
