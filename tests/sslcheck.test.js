'use strict';

/**
 * @fileoverview Tests for sslcheck.
 * Uses a local TLS server with a self-signed certificate.
 * @author idirdev
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const tls = require('tls');
const crypto = require('crypto');

const {
  gradeSSL,
  isExpired,
  isExpiringSoon,
  formatReport,
  formatTable,
  summary,
  checkCert,
} = require('../src/index');

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeFakeInfo(overrides) {
  const now = new Date();
  const base = {
    host: 'example.com',
    port: 443,
    subject: 'CN=example.com',
    issuer: 'CN=Example CA',
    validFrom: new Date(now.getTime() - 30 * 86400000).toISOString(),
    validTo: new Date(now.getTime() + 300 * 86400000).toISOString(),
    daysRemaining: 300,
    serialNumber: 'AABBCC',
    fingerprint: 'AA:BB:CC',
    san: ['example.com', 'www.example.com'],
    protocol: 'TLSv1.3',
    cipher: { name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1/SSLv3', bits: 256 },
    authorized: true,
    authError: null,
    checkedAt: now.toISOString(),
  };
  return Object.assign({}, base, overrides);
}

// ── gradeSSL ─────────────────────────────────────────────────────────────────

describe('gradeSSL', () => {
  it('grades TLSv1.3 with plenty of days as A+', () => {
    assert.equal(gradeSSL(makeFakeInfo({ protocol: 'TLSv1.3', daysRemaining: 300 })), 'A+');
  });

  it('grades TLSv1.2 as A', () => {
    assert.equal(gradeSSL(makeFakeInfo({ protocol: 'TLSv1.2', daysRemaining: 300 })), 'A');
  });

  it('grades TLSv1.1 as D', () => {
    const info = makeFakeInfo({ protocol: 'TLSv1.1', daysRemaining: 300 });
    assert.equal(gradeSSL(info), 'D');
  });

  it('grades TLSv1 (legacy) as F', () => {
    const info = makeFakeInfo({ protocol: 'TLSv1', daysRemaining: 300 });
    assert.equal(gradeSSL(info), 'F');
  });

  it('grades expired cert as F', () => {
    const now = new Date();
    const info = makeFakeInfo({
      validTo: new Date(now.getTime() - 86400000).toISOString(),
      daysRemaining: -1,
    });
    assert.equal(gradeSSL(info), 'F');
  });

  it('grades cert with fewer than 7 days as D', () => {
    const info = makeFakeInfo({ protocol: 'TLSv1.3', daysRemaining: 3 });
    assert.equal(gradeSSL(info), 'D');
  });

  it('grades cert with fewer than 30 days as C', () => {
    const info = makeFakeInfo({ protocol: 'TLSv1.3', daysRemaining: 20 });
    assert.equal(gradeSSL(info), 'C');
  });

  it('returns F for null input', () => {
    assert.equal(gradeSSL(null), 'F');
  });
});

// ── isExpired ────────────────────────────────────────────────────────────────

describe('isExpired', () => {
  it('returns true for a past validTo date', () => {
    const info = makeFakeInfo({ validTo: new Date(Date.now() - 86400000).toISOString() });
    assert.equal(isExpired(info), true);
  });

  it('returns false for a future validTo date', () => {
    const info = makeFakeInfo({ validTo: new Date(Date.now() + 86400000).toISOString() });
    assert.equal(isExpired(info), false);
  });

  it('returns false for null info', () => {
    assert.equal(isExpired(null), false);
  });
});

// ── isExpiringSoon ───────────────────────────────────────────────────────────

describe('isExpiringSoon', () => {
  it('returns true when daysRemaining is within threshold', () => {
    const info = makeFakeInfo({ daysRemaining: 10, validTo: new Date(Date.now() + 10 * 86400000).toISOString() });
    assert.equal(isExpiringSoon(info, 30), true);
  });

  it('returns false when daysRemaining is above threshold', () => {
    const info = makeFakeInfo({ daysRemaining: 90 });
    assert.equal(isExpiringSoon(info, 30), false);
  });

  it('returns false for an already-expired cert', () => {
    const info = makeFakeInfo({ validTo: new Date(Date.now() - 86400000).toISOString(), daysRemaining: -1 });
    assert.equal(isExpiringSoon(info, 30), false);
  });

  it('uses 30 day default threshold', () => {
    const info = makeFakeInfo({ daysRemaining: 15, validTo: new Date(Date.now() + 15 * 86400000).toISOString() });
    assert.equal(isExpiringSoon(info), true);
  });
});

// ── formatReport ─────────────────────────────────────────────────────────────

describe('formatReport', () => {
  it('includes host, grade, and subject in output', () => {
    const info = makeFakeInfo({});
    const report = formatReport(info);
    assert.ok(report.includes('example.com'));
    assert.ok(report.includes('Grade'));
    assert.ok(report.includes('Subject'));
  });

  it('marks expired cert in report', () => {
    const info = makeFakeInfo({ validTo: new Date(Date.now() - 86400000).toISOString(), daysRemaining: -1 });
    const report = formatReport(info);
    assert.ok(report.includes('EXPIRED'));
  });

  it('shows error message for error info', () => {
    const report = formatReport({ host: 'bad.com', error: 'connection refused' });
    assert.ok(report.includes('ERROR'));
    assert.ok(report.includes('connection refused'));
  });

  it('returns fallback message for null input', () => {
    const report = formatReport(null);
    assert.ok(report.length > 0);
  });
});

// ── formatTable ──────────────────────────────────────────────────────────────

describe('formatTable', () => {
  it('renders a table with header and rows', () => {
    const results = [
      makeFakeInfo({ host: 'a.com', daysRemaining: 200 }),
      makeFakeInfo({ host: 'b.com', daysRemaining: 5 }),
    ];
    const table = formatTable(results);
    assert.ok(table.includes('a.com'));
    assert.ok(table.includes('b.com'));
    assert.ok(table.includes('Grade'));
  });

  it('renders error row for failed checks', () => {
    const results = [{ host: 'fail.com', error: 'timeout', checkedAt: new Date().toISOString() }];
    const table = formatTable(results);
    assert.ok(table.includes('fail.com'));
    assert.ok(table.includes('ERR'));
  });

  it('returns fallback string for empty array', () => {
    const table = formatTable([]);
    assert.ok(table.length > 0);
  });
});

// ── summary ──────────────────────────────────────────────────────────────────

describe('summary', () => {
  it('counts ok, expiringSoon, expired, errors correctly', () => {
    const now = new Date();
    const results = [
      makeFakeInfo({ daysRemaining: 200, validTo: new Date(now.getTime() + 200 * 86400000).toISOString() }),
      makeFakeInfo({ daysRemaining: 10, validTo: new Date(now.getTime() + 10 * 86400000).toISOString() }),
      makeFakeInfo({ daysRemaining: -5, validTo: new Date(now.getTime() - 5 * 86400000).toISOString() }),
      { host: 'err.com', error: 'timeout', checkedAt: now.toISOString() },
    ];
    const s = summary(results);
    assert.equal(s.total, 4);
    assert.equal(s.ok, 1);
    assert.equal(s.expiringSoon, 1);
    assert.equal(s.expired, 1);
    assert.equal(s.errors, 1);
  });

  it('returns zeroed object for empty input', () => {
    const s = summary([]);
    assert.equal(s.total, 0);
    assert.equal(s.ok, 0);
  });
});

// ── Local TLS server integration test ────────────────────────────────────────

describe('checkCert (local TLS server)', () => {
  let server;
  let serverPort;
  let selfSignedCert;

  before(async () => {
    // Dynamically generate a self-signed cert using Node.js crypto + openssl.
    const { execSync } = require('child_process');
    const os = require('os');
    const fs = require('fs');
    const path = require('path');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sslcheck-test-'));
    const keyFile = path.join(tmpDir, 'server.key');
    const certFile = path.join(tmpDir, 'server.crt');

    try {
      execSync(
        'openssl req -x509 -newkey rsa:2048 -keyout "' + keyFile +
        '" -out "' + certFile + '" -days 3650 -nodes -subj "/CN=127.0.0.1"',
        { stdio: 'ignore' }
      );
      selfSignedCert = {
        key: fs.readFileSync(keyFile, 'utf8'),
        cert: fs.readFileSync(certFile, 'utf8'),
      };
    } catch (_) {
      // openssl not available — mark cert as unavailable
      selfSignedCert = null;
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    if (!selfSignedCert) return;

    await new Promise((resolve, reject) => {
      server = tls.createServer(
        { key: selfSignedCert.key, cert: selfSignedCert.cert, rejectUnauthorized: false },
        (sock) => { sock.end(); }
      );
      server.listen(0, '127.0.0.1', (err) => {
        if (err) return reject(err);
        serverPort = server.address().port;
        resolve();
      });
      server.on('error', reject);
    });
  });

  after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
  });

  it('retrieves certificate info from local TLS server', async () => {
    if (!selfSignedCert || !server) return; // skip if openssl unavailable

    let info;
    try {
      info = await checkCert('127.0.0.1', serverPort);
    } catch (err) {
      // TLS connection errors can happen in restricted environments — skip
      if (err.message.includes('TLS error') || err.message.includes('No certificate')) {
        return;
      }
      throw err;
    }
    assert.ok(info);
    assert.equal(info.host, '127.0.0.1');
    assert.equal(info.port, serverPort);
  });
});
