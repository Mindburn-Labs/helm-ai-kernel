#!/usr/bin/env node
// Exercise the archived Console-including Linux release layout through its
// public launcher. The Playwright dependency is deliberately loaded from the
// exact pinned Console checkout, not from the Kernel repository.
import { execFileSync, spawn } from 'node:child_process';
import { access, lstat, mkdtemp, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const STARTUP_TIMEOUT_MS = 90_000;
const SHUTDOWN_TIMEOUT_MS = 10_000;

function usage() {
  return 'usage: console_layout_browser_smoke.mjs --layout <linux-amd64-layout.tar.gz> --console-checkout <pinned-console-checkout>';
}

function parseArgs(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!['--layout', '--console-checkout'].includes(name) || !value || values.has(name)) {
      throw new Error(usage());
    }
    values.set(name, resolve(value));
  }
  if (args.length !== 4 || values.size !== 2) throw new Error(usage());
  return { layout: values.get('--layout'), consoleCheckout: values.get('--console-checkout') };
}

async function withTimeout(promise, label, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${milliseconds}ms`)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function requireRegularFile(file, label, mode = constants.R_OK) {
  const info = await lstat(file);
  if (!info.isFile()) throw new Error(`${label} must be a regular file: ${file}`);
  await access(file, mode);
}

async function reserveLoopbackPort() {
  return new Promise((resolvePort, reject) => {
    const listener = createServer();
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', () => {
      const address = listener.address();
      if (!address || typeof address === 'string' || address.port <= 0) {
        listener.close(() => reject(new Error('could not reserve a loopback Kernel port')));
        return;
      }
      listener.close((error) => error ? reject(error) : resolvePort(address.port));
    });
  });
}

function sanitizedQuickstartEnv() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key === 'DATABASE_URL' || key.startsWith('HELM_')) delete env[key];
  }
  return env;
}

function waitForExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolveExit) => child.once('exit', resolveExit));
}

async function stopQuickstart(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = waitForExit(child);
  child.kill('SIGTERM');
  try {
    await withTimeout(exited, 'quickstart shutdown', SHUTDOWN_TIMEOUT_MS);
  } catch {
    child.kill('SIGKILL');
    await withTimeout(exited, 'forced quickstart shutdown', SHUTDOWN_TIMEOUT_MS);
  }
}

async function waitForQuickstartReady(child) {
  let stdout = '';
  let stderr = '';
  const ready = new Promise((resolveReady, reject) => {
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      try {
        const summary = JSON.parse(stdout.trim());
        if (summary.operation !== 'start' || typeof summary.console_url !== 'string') {
          reject(new Error('quickstart JSON did not report a Console start URL'));
          return;
        }
        resolveReady(summary);
      } catch {
        // JSON is emitted only after the authenticated sidecar readiness probe;
        // keep waiting while its single document is still arriving.
      }
    });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code, signal) => reject(new Error(`quickstart exited before readiness (code=${code}, signal=${signal})`)));
  });
  try {
    return await withTimeout(ready, 'quickstart Console readiness', STARTUP_TIMEOUT_MS);
  } catch (error) {
    throw new Error(`${error.message}\nquickstart stderr:\n${stderr.slice(-8_000)}\nquickstart stdout:\n${stdout.slice(-8_000)}`);
  }
}

async function proveBrowser(consoleCheckout, consoleURL) {
  const consoleRequire = createRequire(join(consoleCheckout, 'package.json'));
  const { chromium } = consoleRequire('@playwright/test');
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.goto(consoleURL, { waitUntil: 'domcontentloaded', timeout: STARTUP_TIMEOUT_MS });
    const proofBrowser = page.locator('[data-testid="local-proof-browser"]');
    const ribbon = page.locator('[data-testid="local-proof-ribbon"]');
    await Promise.all([
      proofBrowser.waitFor({ state: 'visible', timeout: STARTUP_TIMEOUT_MS }),
      ribbon.waitFor({ state: 'visible', timeout: STARTUP_TIMEOUT_MS }),
    ]);
    const ribbonText = await ribbon.innerText();
    if (!ribbonText.includes('POLICY') || !ribbonText.includes('EVIDENCE')) {
      throw new Error('local proof ribbon did not render policy and evidence state');
    }
  } finally {
    await browser.close();
  }
}

async function main() {
  const { layout, consoleCheckout } = parseArgs(process.argv.slice(2));
  await requireRegularFile(layout, 'Console layout archive');
  await requireRegularFile(join(consoleCheckout, 'package.json'), 'Pinned Console package manifest');

  const tempRoot = await mkdtemp(join(tmpdir(), 'helm-ai-kernel-console-layout-'));
  let quickstart;
  let primaryError;
  try {
    execFileSync('tar', ['-xzf', layout, '-C', tempRoot], { stdio: 'inherit' });
    const layoutRoot = join(tempRoot, 'helm-ai-kernel-linux-amd64');
    const binary = join(layoutRoot, 'helm-ai-kernel');
    await requireRegularFile(binary, 'Archived helm-ai-kernel binary', constants.X_OK);
    const port = await reserveLoopbackPort();
    quickstart = spawn(binary, [
      'quickstart', '--console', '--console-port', '0', '--no-open', '--offline',
      '--data-dir', join(tempRoot, 'quickstart-data'), '--port', String(port), '--json',
    ], { cwd: layoutRoot, env: sanitizedQuickstartEnv(), stdio: ['ignore', 'pipe', 'pipe'] });
    const summary = await waitForQuickstartReady(quickstart);
    const consoleURL = new URL(summary.console_url);
    if (consoleURL.protocol !== 'http:' || consoleURL.hostname !== '127.0.0.1' || !consoleURL.port) {
      throw new Error(`quickstart reported a non-loopback Console URL: ${summary.console_url}`);
    }
    await proveBrowser(consoleCheckout, consoleURL.toString());
    console.log(`Console archived-layout browser smoke passed: ${consoleURL}`);
  } catch (error) {
    primaryError = error;
  }

  try {
    await stopQuickstart(quickstart);
    await rm(tempRoot, { recursive: true, force: true });
  } catch (cleanupError) {
    primaryError = primaryError ? new AggregateError([primaryError, cleanupError], 'Console browser smoke and cleanup failed') : cleanupError;
  }
  if (primaryError) throw primaryError;
}

main().catch((error) => {
  console.error(`console archived-layout browser smoke failed: ${error.stack ?? error.message}`);
  process.exitCode = 1;
});
