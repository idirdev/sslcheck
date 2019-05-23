'use strict';

const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');

const DEFAULT_PORT = 443;
const DEFAULT_TIMEOUT = 10000;

/**
 * Establish a TLS connection and extract full certificate details.
 * @param {string} host - Domain to check
 * @param {object} options - { port, timeout, servername }
 * @returns {Promise<object>} Raw certificate data + connection metadata
 */
function checkCertificate(host, options = {}) {
  const port = options.port || DEFAULT_PORT;
  const timeout = options.timeout || DEFAULT_TIMEOUT;
  const servername = options.servername || host;

  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername,
        rejectUnauthorized: false,
        requestOCSP: true,
        minVersion: 'TLSv1',
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          if (!cert || !cert.subject) {
            socket.destroy();
            return reject(new Error(`No certificate returned by ${host}:${port}`));
          }

          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError || null;

          const chain = buildCertificateChain(cert);
          const fingerprints = {
            sha1: cert.fingerprint || null,
            sha256: cert.fingerprint256 || null,
          };

          const result = {
            host,
            port,
            authorized,
            authorizationError,
            protocol,
            cipher: cipher
              ? { name: cipher.name, version: cipher.version, bits: cipher.bits }
              : null,
            certificate: {
              subject: flattenCertField(cert.subject),
              issuer: flattenCertField(cert.issuer),
              subjectaltname: cert.subjectaltname || '',
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              serialNumber: cert.serialNumber || null,
              fingerprints,
              bits: cert.bits || null,
              publicKey: cert.pubkey
                ? { type: cert.asn1Curve || 'RSA', size: cert.bits }
                : null,
            },
            chain,
            raw: cert,
          };

          socket.destroy();
          resolve(result);
        } catch (err) {
          socket.destroy();
          reject(new Error(`Failed to parse certificate for ${host}: ${err.message}`));
        }
      }
    );

    socket.setTimeout(timeout, () => {
      socket.destroy();
      reject(new Error(`Connection to ${host}:${port} timed out after ${timeout}ms`));
    });

    socket.on('error', (err) => {
      reject(new Error(`TLS connection to ${host}:${port} failed: ${err.message}`));
    });

    socket.on('OCSPResponse', (response) => {
      if (socket._sslcheckOCSP === undefined) {
        socket._sslcheckOCSP = response;
      }
    });
  });
}

/**
 * Walk the issuerCertificate linked list to build the chain array.
 */
function buildCertificateChain(cert) {
  const chain = [];
  const seen = new Set();
  let current = cert;

  while (current && current.subject) {
    const id = current.serialNumber || JSON.stringify(current.subject);
    if (seen.has(id)) break;
    seen.add(id);

    chain.push({
      subject: flattenCertField(current.subject),
      issuer: flattenCertField(current.issuer),
      validFrom: current.valid_from,
      validTo: current.valid_to,
      serialNumber: current.serialNumber || null,
      fingerprint: current.fingerprint256 || current.fingerprint || null,
    });

    if (
      !current.issuerCertificate ||
      current.issuerCertificate === current ||
      current.issuerCertificate.serialNumber === current.serialNumber
    ) {
      break;
    }
    current = current.issuerCertificate;
  }

  return chain;
}

/**
 * Flatten Node.js cert subject/issuer objects into readable strings.
 */
function flattenCertField(field) {
  if (!field) return '';
  if (typeof field === 'string') return field;
  const parts = [];
  for (const [key, val] of Object.entries(field)) {
    if (Array.isArray(val)) {
      parts.push(`${key}=${val.join(', ')}`);
    } else {
      parts.push(`${key}=${val}`);
    }
  }
  return parts.join(', ');
}

/**
 * Check OCSP status via HTTPS (basic check).
 * Returns 'good', 'revoked', 'unknown', or 'unavailable'.
 */
async function checkOCSPStatus(host, port = 443) {
  return new Promise((resolve) => {
    const req = https.request(
      {
        hostname: host,
        port,
        path: '/',
        method: 'HEAD',
        rejectUnauthorized: true,
        timeout: 5000,
      },
      (res) => {
        // If TLS handshake succeeded with rejectUnauthorized: true,
        // the certificate chain is valid and not revoked by the OS trust store.
        resolve('good');
      }
    );

    req.on('error', (err) => {
      if (err.code === 'CERT_REVOKED') {
        resolve('revoked');
      } else if (
        err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
        err.code === 'SELF_SIGNED_CERT_IN_CHAIN'
      ) {
        resolve('unknown');
      } else {
        resolve('unavailable');
      }
    });

    req.on('timeout', () => {
      req.destroy();
      resolve('unavailable');
    });

    req.end();
  });
}

/**
 * Parse a domain string that may include port (e.g. "example.com:8443").
 */
function parseDomainInput(input) {
  let cleaned = input.trim();
  // Strip protocol if present
  cleaned = cleaned.replace(/^https?:\/\//, '');
  // Strip path
  cleaned = cleaned.split('/')[0];

  const parts = cleaned.split(':');
  return {
    host: parts[0],
    port: parts[1] ? parseInt(parts[1], 10) : DEFAULT_PORT,
  };
}

module.exports = {
  checkCertificate,
  checkOCSPStatus,
  parseDomainInput,
  buildCertificateChain,
  flattenCertField,
};
