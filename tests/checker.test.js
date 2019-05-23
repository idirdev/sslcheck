'use strict';

const assert = require('assert');
const {
  analyzeExpiry,
  parseSANs,
  analyzeProtocol,
  analyzeChain,
  EXPIRY_WARNING_DAYS,
} = require('../src/analyzer');
const { parseDomainInput, flattenCertField } = require('../src/checker');

let passed = 0;
let failed = 0;
let total = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    passed++;
    console.log('  + ' + name);
  } catch (err) {
    failed++;
    console.log('  X ' + name);
    console.log('    ' + err.message);
  }
}

function suite(name, fn) {
  console.log('\n' + name);
  fn();
}

// --- parseDomainInput ---

suite('parseDomainInput', () => {
  test('parses plain domain', () => {
    const r = parseDomainInput('example.com');
    assert.strictEqual(r.host, 'example.com');
    assert.strictEqual(r.port, 443);
  });

  test('parses domain with port', () => {
    const r = parseDomainInput('example.com:8443');
    assert.strictEqual(r.host, 'example.com');
    assert.strictEqual(r.port, 8443);
  });

  test('strips https:// prefix', () => {
    const r = parseDomainInput('https://example.com');
    assert.strictEqual(r.host, 'example.com');
    assert.strictEqual(r.port, 443);
  });

  test('strips http:// prefix and path', () => {
    const r = parseDomainInput('http://example.com/path/to/page');
    assert.strictEqual(r.host, 'example.com');
  });

  test('trims whitespace', () => {
    const r = parseDomainInput('  example.com  ');
    assert.strictEqual(r.host, 'example.com');
  });
});

// --- flattenCertField ---

suite('flattenCertField', () => {
  test('flattens object fields', () => {
    const result = flattenCertField({ CN: 'example.com', O: 'Example Inc' });
    assert.ok(result.includes('CN=example.com'));
    assert.ok(result.includes('O=Example Inc'));
  });

  test('returns empty string for null', () => {
    assert.strictEqual(flattenCertField(null), '');
  });

  test('returns string as-is', () => {
    assert.strictEqual(flattenCertField('already a string'), 'already a string');
  });

  test('handles array values', () => {
    const result = flattenCertField({ CN: ['a.com', 'b.com'] });
    assert.ok(result.includes('CN=a.com, b.com'));
  });
});

// --- analyzeExpiry ---

suite('analyzeExpiry', () => {
  test('reports valid certificate', () => {
    const from = new Date(Date.now() - 30 * 86400000).toISOString();
    const to = new Date(Date.now() + 300 * 86400000).toISOString();
    const result = analyzeExpiry(from, to);
    assert.strictEqual(result.status, 'valid');
    assert.strictEqual(result.isExpired, false);
    assert.strictEqual(result.isExpiringSoon, false);
    assert.ok(result.daysRemaining > 200);
  });

  test('reports expired certificate', () => {
    const from = new Date(Date.now() - 365 * 86400000).toISOString();
    const to = new Date(Date.now() - 10 * 86400000).toISOString();
    const result = analyzeExpiry(from, to);
    assert.strictEqual(result.status, 'expired');
    assert.strictEqual(result.isExpired, true);
  });

  test('reports warning for cert expiring within 30 days', () => {
    const from = new Date(Date.now() - 335 * 86400000).toISOString();
    const to = new Date(Date.now() + 15 * 86400000).toISOString();
    const result = analyzeExpiry(from, to);
    assert.strictEqual(result.status, 'warning');
    assert.strictEqual(result.isExpiringSoon, true);
  });

  test('reports critical for cert expiring within 7 days', () => {
    const from = new Date(Date.now() - 358 * 86400000).toISOString();
    const to = new Date(Date.now() + 3 * 86400000).toISOString();
    const result = analyzeExpiry(from, to);
    assert.strictEqual(result.status, 'critical');
  });

  test('reports not_yet_valid for future cert', () => {
    const from = new Date(Date.now() + 10 * 86400000).toISOString();
    const to = new Date(Date.now() + 375 * 86400000).toISOString();
    const result = analyzeExpiry(from, to);
    assert.strictEqual(result.status, 'not_yet_valid');
  });

  test('calculates percentUsed correctly', () => {
    const from = new Date(Date.now() - 100 * 86400000).toISOString();
    const to = new Date(Date.now() + 100 * 86400000).toISOString();
    const result = analyzeExpiry(from, to);
    assert.ok(result.percentUsed >= 48 && result.percentUsed <= 52);
  });
});

// --- parseSANs ---

suite('parseSANs', () => {
  test('parses DNS entries', () => {
    const result = parseSANs('DNS:example.com, DNS:*.example.com');
    assert.deepStrictEqual(result.dns, ['example.com', '*.example.com']);
    assert.strictEqual(result.count, 2);
  });

  test('parses mixed entries', () => {
    const result = parseSANs('DNS:example.com, IP Address:127.0.0.1, email:test@test.com');
    assert.strictEqual(result.dns.length, 1);
    assert.strictEqual(result.ip.length, 1);
    assert.strictEqual(result.email.length, 1);
    assert.strictEqual(result.count, 3);
  });

  test('returns empty for null input', () => {
    const result = parseSANs(null);
    assert.strictEqual(result.count, 0);
    assert.deepStrictEqual(result.dns, []);
  });

  test('returns empty for empty string', () => {
    const result = parseSANs('');
    assert.strictEqual(result.count, 0);
  });
});

// --- analyzeProtocol ---

suite('analyzeProtocol', () => {
  test('rates TLSv1.3 as A+', () => {
    const result = analyzeProtocol('TLSv1.3', { name: 'TLS_AES_256_GCM_SHA384', bits: 256 });
    assert.strictEqual(result.grade, 'A+');
    assert.strictEqual(result.isSecure, true);
    assert.strictEqual(result.cipher.strength, 'strong');
  });

  test('rates TLSv1.2 as A', () => {
    const result = analyzeProtocol('TLSv1.2', { name: 'ECDHE-RSA-AES128-GCM-SHA256', bits: 128 });
    assert.strictEqual(result.grade, 'A');
    assert.strictEqual(result.isSecure, true);
    assert.strictEqual(result.cipher.strength, 'adequate');
  });

  test('rates TLSv1 as F and insecure', () => {
    const result = analyzeProtocol('TLSv1', { name: 'AES128-SHA', bits: 128 });
    assert.strictEqual(result.grade, 'F');
    assert.strictEqual(result.isSecure, false);
  });

  test('detects weak cipher components', () => {
    const result = analyzeProtocol('TLSv1.2', { name: 'DES-CBC3-SHA', bits: 56 });
    assert.ok(result.cipher.warnings.length > 0);
    assert.strictEqual(result.cipher.strength, 'weak');
  });

  test('handles null cipher', () => {
    const result = analyzeProtocol('TLSv1.3', null);
    assert.strictEqual(result.cipher, null);
  });

  test('recommends upgrade for TLSv1.2', () => {
    const result = analyzeProtocol('TLSv1.2', { name: 'AES256-SHA', bits: 256 });
    assert.ok(result.recommendations.length > 0);
  });
});

// --- analyzeChain ---

suite('analyzeChain', () => {
  test('analyzes valid chain', () => {
    const chain = [
      {
        subject: 'CN=example.com',
        issuer: 'CN=Intermediate CA',
        validFrom: new Date(Date.now() - 30 * 86400000).toISOString(),
        validTo: new Date(Date.now() + 300 * 86400000).toISOString(),
        serialNumber: '01',
      },
      {
        subject: 'CN=Intermediate CA',
        issuer: 'CN=Root CA',
        validFrom: new Date(Date.now() - 365 * 86400000).toISOString(),
        validTo: new Date(Date.now() + 3650 * 86400000).toISOString(),
        serialNumber: '02',
      },
    ];
    const result = analyzeChain(chain);
    assert.strictEqual(result.length, 2);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.issues.length, 0);
    assert.strictEqual(result.certificates[0].label, 'leaf');
    assert.strictEqual(result.certificates[1].label, 'intermediate');
  });

  test('detects expired chain certificate', () => {
    const chain = [
      {
        subject: 'CN=example.com',
        issuer: 'CN=Bad CA',
        validFrom: new Date(Date.now() - 400 * 86400000).toISOString(),
        validTo: new Date(Date.now() - 5 * 86400000).toISOString(),
        serialNumber: '01',
      },
    ];
    const result = analyzeChain(chain);
    assert.strictEqual(result.valid, false);
    assert.ok(result.issues.length > 0);
  });

  test('handles empty chain', () => {
    const result = analyzeChain([]);
    assert.strictEqual(result.length, 0);
    assert.strictEqual(result.valid, false);
  });

  test('identifies self-signed root', () => {
    const chain = [
      {
        subject: 'CN=Root CA',
        issuer: 'CN=Root CA',
        validFrom: new Date(Date.now() - 365 * 86400000).toISOString(),
        validTo: new Date(Date.now() + 3650 * 86400000).toISOString(),
        serialNumber: '01',
      },
    ];
    const result = analyzeChain(chain);
    assert.strictEqual(result.certificates[0].label, 'root');
  });
});

// --- Summary ---

console.log('\n' + '-'.repeat(40));
console.log('Results: ' + passed + '/' + total + ' passed, ' + failed + ' failed');
if (failed > 0) {
  process.exit(1);
} else {
  console.log('All tests passed!\n');
}
