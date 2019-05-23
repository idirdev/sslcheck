'use strict';

/**
 * @fileoverview Check SSL/TLS certificates on remote domains.
 * Uses only Node.js built-in tls and net modules.
 * @module sslcheck
 * @author idirdev
 */

const tls = require('tls');

const DEFAULT_PORT = 443;
const DEFAULT_TIMEOUT = 10000;

/**
 * Connect to a host via TLS and return certificate details.
 *
 * @param {string} domain  - Hostname to check (may include port as "host:port").
 * @param {number} [port=443] - TLS port (overridden if domain includes port).
 * @returns {Promise<Object>} Certificate information object.
 */
function checkCert(domain, port) {
  const parsed = _parseDomain(domain);
  const host = parsed.host;
  const resolvedPort = parsed.port || port || DEFAULT_PORT;

  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port: resolvedPort,
        servername: host,
        rejectUnauthorized: false,
        minVersion: 'TLSv1',
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            return reject(new Error('No certificate returned from ' + host + ':' + resolvedPort));
          }

          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();
          const authorized = socket.authorized;

          const now = new Date();
          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          const daysRemaining = validTo
            ? Math.floor((validTo - now) / 86400000)
            : null;

          const san = _parseSAN(cert.subjectaltname || '');

          const info = {
            host,
            port: resolvedPort,
            subject: _flattenField(cert.subject),
            issuer: _flattenField(cert.issuer),
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            daysRemaining,
            serialNumber: cert.serialNumber || null,
            fingerprint: cert.fingerprint256 || cert.fingerprint || null,
            san,
            protocol: protocol || null,
            cipher: cipher
              ? { name: cipher.name, version: cipher.version, bits: cipher.bits }
              : null,
            authorized,
            authError: authorized ? null : (socket.authorizationError || null),
            checkedAt: now.toISOString(),
          };

          socket.destroy();
          resolve(info);
        } catch (err) {
          socket.destroy();
          reject(new Error('Failed to parse certificate: ' + err.message));
        }
      }
    );

    socket.setTimeout(DEFAULT_TIMEOUT, () => {
      socket.destroy();
      reject(new Error('Connection to ' + host + ':' + resolvedPort + ' timed out'));
    });

    socket.on('error', (err) => {
      reject(new Error('TLS error for ' + host + ':' + resolvedPort + ' — ' + err.message));
    });
  });
}

/**
 * Check multiple domains in parallel.
 *
 * @param {string[]} domains - Array of domain strings.
 * @param {number}   [port=443] - Default TLS port.
 * @returns {Promise<Object[]>} Array of cert info objects (errors are included with an `error` key).
 */
async function checkMultiple(domains, port) {
  const results = await Promise.allSettled(
    domains.map((d) => checkCert(d, port))
  );
  return results.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    return { host: domains[i], error: r.reason.message, checkedAt: new Date().toISOString() };
  });
}

/**
 * Grade an SSL certificate based on days remaining and protocol.
 *
 * @param {Object} info - Certificate info from checkCert().
 * @returns {string} Grade: "A+" | "A" | "B" | "C" | "D" | "F".
 */
function gradeSSL(info) {
  if (!info || info.error) return 'F';
  if (isExpired(info)) return 'F';

  const days = info.daysRemaining;
  const proto = info.protocol;

  // Protocol downgrades
  if (proto === 'TLSv1' || proto === 'SSLv3') return 'F';
  if (proto === 'TLSv1.1') return 'D';

  // Days-based grading
  if (days !== null && days < 7) return 'D';
  if (days !== null && days < 30) return 'C';

  if (proto === 'TLSv1.2') return 'A';
  if (proto === 'TLSv1.3') return 'A+';

  return 'B';
}

/**
 * Check if a certificate is expired.
 *
 * @param {Object} info - Certificate info.
 * @returns {boolean}
 */
function isExpired(info) {
  if (!info || !info.validTo) return false;
  return new Date(info.validTo) < new Date();
}

/**
 * Check if a certificate is expiring within the given number of days.
 *
 * @param {Object} info    - Certificate info.
 * @param {number} [days=30] - Warning threshold in days.
 * @returns {boolean}
 */
function isExpiringSoon(info, days) {
  days = days == null ? 30 : days;
  if (!info || isExpired(info) || info.daysRemaining === null) return false;
  return info.daysRemaining <= days;
}

/**
 * Format a single certificate info object as a human-readable report string.
 *
 * @param {Object} info - Certificate info from checkCert().
 * @returns {string} Multi-line report.
 */
function formatReport(info) {
  if (!info) return 'No certificate info available.\n';
  if (info.error) return 'ERROR for ' + info.host + ': ' + info.error + '\n';

  const grade = gradeSSL(info);
  const expired = isExpired(info) ? ' [EXPIRED]' : '';
  const expiringSoon = !isExpired(info) && isExpiringSoon(info) ? ' [EXPIRING SOON]' : '';
  const daysLabel = info.daysRemaining !== null
    ? info.daysRemaining + ' days remaining'
    : 'unknown';

  const lines = [
    'Host        : ' + info.host + ':' + info.port,
    'Grade       : ' + grade,
    'Subject     : ' + (info.subject || 'N/A'),
    'Issuer      : ' + (info.issuer || 'N/A'),
    'Valid From  : ' + (info.validFrom || 'N/A'),
    'Valid To    : ' + (info.validTo || 'N/A') + expired + expiringSoon,
    'Days Left   : ' + daysLabel,
    'Protocol    : ' + (info.protocol || 'N/A'),
    'Cipher      : ' + (info.cipher ? info.cipher.name : 'N/A'),
    'Fingerprint : ' + (info.fingerprint || 'N/A'),
    'Serial      : ' + (info.serialNumber || 'N/A'),
    'SAN         : ' + (info.san.length ? info.san.join(', ') : 'none'),
    'Authorized  : ' + (info.authorized ? 'yes' : 'no' + (info.authError ? ' (' + info.authError + ')' : '')),
    'Checked At  : ' + info.checkedAt,
  ];

  return lines.join('\n') + '\n';
}

/**
 * Format multiple cert info objects as an aligned text table.
 *
 * @param {Object[]} results - Array of cert info objects.
 * @returns {string} Formatted table string.
 */
function formatTable(results) {
  if (!results || results.length === 0) return 'No results.\n';

  const COL = { host: 30, grade: 6, days: 8, proto: 10, expires: 28, status: 14 };

  const pad = (s, n) => String(s || '').padEnd(n).slice(0, n);
  const header = [
    pad('Host', COL.host),
    pad('Grade', COL.grade),
    pad('Days', COL.days),
    pad('Protocol', COL.proto),
    pad('Expires', COL.expires),
    pad('Status', COL.status),
  ].join('  ');

  const sep = '-'.repeat(header.length);
  const rows = results.map((info) => {
    if (info.error) {
      return pad(info.host, COL.host) + '  ' + pad('ERR', COL.grade) + '  ' +
        pad('-', COL.days) + '  ' + pad('-', COL.proto) + '  ' +
        pad('-', COL.expires) + '  ' + pad('error', COL.status);
    }
    const grade = gradeSSL(info);
    const status = isExpired(info)
      ? 'EXPIRED'
      : isExpiringSoon(info)
        ? 'EXPIRING SOON'
        : 'OK';
    return [
      pad(info.host, COL.host),
      pad(grade, COL.grade),
      pad(info.daysRemaining !== null ? info.daysRemaining : '-', COL.days),
      pad(info.protocol || '-', COL.proto),
      pad(info.validTo || '-', COL.expires),
      pad(status, COL.status),
    ].join('  ');
  });

  return [sep, header, sep, ...rows, sep].join('\n') + '\n';
}

/**
 * Produce a summary object from multiple check results.
 *
 * @param {Object[]} results - Array of cert info objects.
 * @returns {Object} Summary with counts and lists.
 */
function summary(results) {
  if (!results || results.length === 0) {
    return { total: 0, ok: 0, expiringSoon: 0, expired: 0, errors: 0, grades: {} };
  }

  const grades = {};
  let ok = 0;
  let expiringSoonCount = 0;
  let expired = 0;
  let errors = 0;

  for (const info of results) {
    if (info.error) {
      errors++;
      continue;
    }
    if (isExpired(info)) {
      expired++;
    } else if (isExpiringSoon(info)) {
      expiringSoonCount++;
    } else {
      ok++;
    }
    const g = gradeSSL(info);
    grades[g] = (grades[g] || 0) + 1;
  }

  return {
    total: results.length,
    ok,
    expiringSoon: expiringSoonCount,
    expired,
    errors,
    grades,
  };
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Parse a domain string that may include a port (e.g. "example.com:8443").
 * @private
 */
function _parseDomain(domain) {
  let s = (domain || '').trim().replace(/^https?:\/\//, '').split('/')[0];
  const parts = s.split(':');
  return {
    host: parts[0],
    port: parts[1] ? parseInt(parts[1], 10) : null,
  };
}

/**
 * Parse Subject Alternative Names string into an array of names.
 * @private
 */
function _parseSAN(subjectaltname) {
  if (!subjectaltname) return [];
  return subjectaltname
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => {
      const idx = entry.indexOf(':');
      return idx !== -1 ? entry.slice(idx + 1).trim() : entry;
    });
}

/**
 * Flatten cert subject/issuer fields to a string.
 * @private
 */
function _flattenField(field) {
  if (!field) return '';
  if (typeof field === 'string') return field;
  return Object.entries(field)
    .map(([k, v]) => k + '=' + (Array.isArray(v) ? v.join(', ') : v))
    .join(', ');
}

module.exports = {
  checkCert,
  checkMultiple,
  gradeSSL,
  isExpired,
  isExpiringSoon,
  formatReport,
  formatTable,
  summary,
};
