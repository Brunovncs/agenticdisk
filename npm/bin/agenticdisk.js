#!/usr/bin/env node
'use strict';

// Thin launcher: runs the bundled native binary with the same arguments and stdio, so
// `npx -y agenticdisk mcp` is the MCP server and `npx -y agenticdisk overview` the CLI.

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

function fail(message) {
  // Same shape as the binary's own errors, so agents parse one format. As an MCP server stdout
  // carries JSON-RPC only, so the client gets the reason on stderr (its server log).
  const out = process.argv[2] === 'mcp' ? process.stderr : process.stdout;
  out.write(JSON.stringify({ tool: 'agenticdisk', error: message }) + '\n');
  process.exit(1);
}

if (process.platform !== 'win32') {
  fail('agenticdisk currently supports Windows 10/11 only.');
}

const exe = path.join(__dirname, '..', 'vendor', 'agenticdisk.exe');
if (!fs.existsSync(exe)) {
  fail(`agenticdisk binary missing at ${exe}; reinstall the package.`);
}

const child = spawn(exe, process.argv.slice(2), { stdio: 'inherit', windowsHide: true });
for (const signal of ['SIGINT', 'SIGTERM', 'SIGBREAK']) {
  process.on(signal, () => child.kill(signal));
}
child.on('error', (err) => fail(`could not start agenticdisk: ${err.message}`));
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
