'use strict';

const EXPIRY_WARNING_DAYS = 30;
const EXPIRY_CRITICAL_DAYS = 7;

const PROTOCOL_RATINGS = {
  'TLSv1.3': { grade: 'A+', secure: true },
  'TLSv1.2': { grade: 'A', secure: true },
  'TLSv1.1': { grade: 'C', secure: false },
  'TLSv1': { grade: 'F', secure: false },
  'SSLv3': { grade: 'F', secure: false },
};

const WEAK_CIPHERS = [
  'RC4', 'DES', 'MD5', '3DES', 'NULL', 'EXPORT', 'anon',
];

/**
 * Analyze certificate expiry.
 * @param {string} validFrom - Certificate start date
 * @param {string} validTo - Certificate end date
 * @returns {object} Expiry analysis
 */
function analyzeExpiry(validFrom, validTo) {
  const now = new Date();
  const from = new Date(validFrom);
  const to = new Date(validTo);
  const daysRemaining = Math.floor((to - now) / (1000 * 60 * 60 * 24));
  const totalDays = Math.floor((to - from) / (1000 * 60 * 60 * 24));
  const elapsed = Math.floor((now - from) / (1000 * 60 * 60 * 24));

  let status;
  if (now < from) {
    status = 'not_yet_valid';
  } else if (now > to) {
    status = 'expired';
  } else if (daysRemaining <= EXPIRY_CRITICAL_DAYS) {
    status = 'critical';
  } else if (daysRemaining <= EXPIRY_WARNING_DAYS) {
    status = 'warning';
  } else {
    status = 'valid';
  }

  return {
    validFrom: from.toISOString(),
    validTo: to.toISOString(),
    daysRemaining,
    totalDays,
    elapsedDays: elapsed,
    percentUsed: totalDays > 0 ? Math.round((elapsed / totalDays) * 100) : 0,
    status,
    isExpired: now > to,
    isExpiringSoon: daysRemaining <= EXPIRY_WARNING_DAYS && daysRemaining > 0,
  };
}

/**
 * Parse Subject Alternative Names from the subjectaltname string.
 * @param {string} subjectaltname - e.g. "DNS:example.com, DNS:*.example.com"
 * @returns {object} Parsed SANs by type
 */
function parseSANs(subjectaltname) {
  if (!subjectaltname) return { dns: [], ip: [], email: [], uri: [], count: 0 };

  const entries = subjectaltname.split(',').map((s) => s.trim());
  const result = { dns: [], ip: [], email: [], uri: [] };

  for (const entry of entries) {
    const [type, ...valueParts] = entry.split(':');
    const value = valueParts.join(':');
    const key = type.toLowerCase().trim();

    if (key === 'dns') result.dns.push(value);
    else if (key === 'ip' || key === 'ip address') result.ip.push(value);
    else if (key === 'email') result.email.push(value);
    else if (key === 'uri') result.uri.push(value);
  }

  result.count = result.dns.length + result.ip.length + result.email.length + result.uri.length;
  return result;
}

/**
 * Analyze the TLS protocol and cipher suite.
 * @param {string} protocol - e.g. "TLSv1.3"
 * @param {object} cipher - { name, version, bits }
 * @returns {object} Protocol analysis
 */
function analyzeProtocol(protocol, cipher) {
  const rating = PROTOCOL_RATINGS[protocol] || { grade: '?', secure: false };

  let cipherStrength = 'unknown';
  let cipherWarnings = [];

  if (cipher) {
    if (cipher.bits && cipher.bits >= 256) cipherStrength = 'strong';
    else if (cipher.bits && cipher.bits >= 128) cipherStrength = 'adequate';
    else cipherStrength = 'weak';

    for (const weak of WEAK_CIPHERS) {
      if (cipher.name && cipher.name.toUpperCase().includes(weak)) {
        cipherWarnings.push(`Weak cipher component detected: ${weak}`);
      }
    }
  }

  return {
    version: protocol,
    grade: rating.grade,
    isSecure: rating.secure,
    cipher: cipher
      ? {
          name: cipher.name,
          bits: cipher.bits,
          strength: cipherStrength,
          warnings: cipherWarnings,
        }
      : null,
    recommendations: getProtocolRecommendations(protocol, cipher),
  };
}

/**
 * Analyze the certificate chain.
 * @param {Array} chain - Array of certificate objects
 * @returns {object} Chain analysis
 */
function analyzeChain(chain) {
  if (!chain || chain.length === 0) {
    return {
      length: 0,
      valid: false,
      issues: ['No certificate chain available'],
      certificates: [],
    };
  }

  const issues = [];
  const certificates = chain.map((cert, index) => {
    const expiry = analyzeExpiry(cert.validFrom, cert.validTo);
    const isRoot = cert.subject === cert.issuer;
    const label =
      isRoot ? 'root' : index === 0 ? 'leaf' : 'intermediate';

    if (expiry.isExpired) {
      issues.push(`${label} certificate expired (${cert.subject})`);
    } else if (expiry.isExpiringSoon) {
      issues.push(
        `${label} certificate expiring in ${expiry.daysRemaining} days (${cert.subject})`
      );
    }

    return {
      label,
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      fingerprint: cert.fingerprint,
      expiry,
    };
  });

  return {
    length: chain.length,
    valid: issues.length === 0,
    issues,
    certificates,
  };
}

/**
 * Generate a full analysis report from raw check data.
 */
function generateReport(checkResult, ocspStatus) {
  const { certificate, chain, protocol, cipher, authorized, authorizationError } =
    checkResult;

  const expiry = analyzeExpiry(certificate.validFrom, certificate.validTo);
  const sans = parseSANs(certificate.subjectaltname);
  const protocolAnalysis = analyzeProtocol(protocol, cipher);
  const chainAnalysis = analyzeChain(chain);

  const warnings = [];
  if (expiry.isExpired) warnings.push('Certificate has EXPIRED');
  if (expiry.isExpiringSoon)
    warnings.push(`Certificate expires in ${expiry.daysRemaining} days`);
  if (!authorized)
    warnings.push(`Certificate not trusted: ${authorizationError}`);
  if (!protocolAnalysis.isSecure)
    warnings.push(`Insecure protocol: ${protocol}`);
  if (protocolAnalysis.cipher) {
    warnings.push(...protocolAnalysis.cipher.warnings);
  }
  if (ocspStatus === 'revoked') warnings.push('Certificate has been REVOKED');
  warnings.push(...chainAnalysis.issues);

  let overallGrade;
  if (expiry.isExpired || ocspStatus === 'revoked') overallGrade = 'F';
  else if (!protocolAnalysis.isSecure) overallGrade = 'C';
  else if (warnings.length > 0) overallGrade = 'B';
  else overallGrade = protocolAnalysis.grade;

  return {
    host: checkResult.host,
    port: checkResult.port,
    grade: overallGrade,
    authorized,
    authorizationError,
    certificate: {
      subject: certificate.subject,
      issuer: certificate.issuer,
      serialNumber: certificate.serialNumber,
      fingerprints: certificate.fingerprints,
    },
    expiry,
    sans,
    protocol: protocolAnalysis,
    chain: chainAnalysis,
    ocsp: ocspStatus || 'not_checked',
    warnings,
    checkedAt: new Date().toISOString(),
  };
}

function getProtocolRecommendations(protocol, cipher) {
  const recs = [];
  if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
    recs.push('Upgrade to TLS 1.2 or TLS 1.3');
  }
  if (protocol === 'TLSv1.2') {
    recs.push('Consider enabling TLS 1.3 for improved performance and security');
  }
  if (cipher && cipher.bits && cipher.bits < 128) {
    recs.push('Use a cipher suite with at least 128-bit encryption');
  }
  return recs;
}

module.exports = {
  analyzeExpiry,
  parseSANs,
  analyzeProtocol,
  analyzeChain,
  generateReport,
  EXPIRY_WARNING_DAYS,
  EXPIRY_CRITICAL_DAYS,
};
