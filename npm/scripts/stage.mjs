// Copies the release binary and the license into the npm package, and refuses to package a
// version that differs from the Rust workspace (the MCP server reports the Cargo version).
//
// Runs on `npm pack` / `npm publish` (prepack); build first with `cargo build --release`.

import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pkgDir = join(here, '..');
const repo = join(pkgDir, '..');

const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
const cargo = readFileSync(join(repo, 'Cargo.toml'), 'utf8');
const cargoVersion = /\[workspace\.package\][^[]*?version\s*=\s*"([^"]+)"/s.exec(cargo)?.[1];
if (pkg.version !== cargoVersion) {
  console.error(`npm version ${pkg.version} != Cargo workspace version ${cargoVersion}; bump both together.`);
  process.exit(1);
}

const built = join(repo, 'target', 'release', 'agenticdisk.exe');
if (!existsSync(built)) {
  console.error(`missing ${built}: run \`cargo build --release\` first.`);
  process.exit(1);
}

mkdirSync(join(pkgDir, 'vendor'), { recursive: true });
const staged = join(pkgDir, 'vendor', 'agenticdisk.exe');
copyFileSync(built, staged);
copyFileSync(join(repo, 'LICENSE'), join(pkgDir, 'LICENSE'));

if (statSync(staged).size !== statSync(built).size) {
  console.error('staged binary differs from the build');
  process.exit(1);
}
console.log(`staged agenticdisk ${pkg.version} (${(statSync(staged).size / 1048576).toFixed(1)} MB)`);
