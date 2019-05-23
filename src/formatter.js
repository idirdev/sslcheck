'use strict';

const chalk = require('chalk');
const Table = require('cli-table3');

const GRADE_COLORS = {
  'A+': 'green',
  A: 'green',
  B: 'yellow',
  C: 'red',
  F: 'red',
  '?': 'gray',
};

const STATUS_SYMBOLS = {
  valid: chalk.green('✔'),
  warning: chalk.yellow('⚠'),
  critical: chalk.red('✖'),
  expired: chalk.red('✖'),
  not_yet_valid: chalk.red('✖'),
};

/**
 * Format a report as a styled CLI table.
 */
function formatTable(report) {
  const output = [];

  // Header
  const gradeColor = GRADE_COLORS[report.grade] || 'white';
  output.push('');
  output.push(
    chalk.bold(`  SSL/TLS Report for ${chalk.cyan(report.host)}:${report.port}`)
  );
  output.push(
    `  Grade: ${chalk[gradeColor].bold(report.grade)}  |  Checked: ${formatDate(report.checkedAt)}`
  );
  output.push('');

  // Certificate Info
  const certTable = new Table({
    head: [chalk.bold('Certificate')],
    colWidths: [80],
    style: { head: [], border: ['gray'] },
  });

  certTable.push(
    [formatField('Subject', report.certificate.subject)],
    [formatField('Issuer', report.certificate.issuer)],
    [formatField('Serial', report.certificate.serialNumber)],
    [formatField('SHA-256', report.certificate.fingerprints.sha256)]
  );
  output.push(certTable.toString());

  // Expiry
  const expiryTable = new Table({
    head: [chalk.bold('Validity')],
    colWidths: [80],
    style: { head: [], border: ['gray'] },
  });

  const statusSymbol = STATUS_SYMBOLS[report.expiry.status] || '';
  const daysText = report.expiry.isExpired
    ? chalk.red.bold(`EXPIRED ${Math.abs(report.expiry.daysRemaining)} days ago`)
    : report.expiry.isExpiringSoon
      ? chalk.yellow.bold(`${report.expiry.daysRemaining} days remaining`)
      : chalk.green(`${report.expiry.daysRemaining} days remaining`);

  expiryTable.push(
    [formatField('Valid From', formatDate(report.expiry.validFrom))],
    [formatField('Valid To', formatDate(report.expiry.validTo))],
    [`${statusSymbol} ${daysText}  (${report.expiry.percentUsed}% elapsed)`]
  );
  output.push(expiryTable.toString());

  // SANs
  if (report.sans.count > 0) {
    const sanTable = new Table({
      head: [chalk.bold(`Subject Alternative Names (${report.sans.count})`)],
      colWidths: [80],
      style: { head: [], border: ['gray'] },
    });

    if (report.sans.dns.length > 0) {
      // Show up to 15 SANs, then summarize
      const shown = report.sans.dns.slice(0, 15);
      const sanList = shown.map((d) => chalk.cyan(d)).join(', ');
      const extra =
        report.sans.dns.length > 15
          ? chalk.gray(` ... +${report.sans.dns.length - 15} more`)
          : '';
      sanTable.push([`DNS: ${sanList}${extra}`]);
    }
    if (report.sans.ip.length > 0) {
      sanTable.push([`IP: ${report.sans.ip.join(', ')}`]);
    }
    output.push(sanTable.toString());
  }

  // Protocol & Cipher
  const protoTable = new Table({
    head: [chalk.bold('Protocol & Cipher')],
    colWidths: [80],
    style: { head: [], border: ['gray'] },
  });

  const protoSecure = report.protocol.isSecure
    ? chalk.green('Secure')
    : chalk.red('Insecure');

  protoTable.push(
    [formatField('Protocol', `${report.protocol.version} (${protoSecure})`)],
    [formatField('Grade', chalk[GRADE_COLORS[report.protocol.grade] || 'white'](report.protocol.grade))]
  );

  if (report.protocol.cipher) {
    const c = report.protocol.cipher;
    const strengthColor =
      c.strength === 'strong' ? 'green' : c.strength === 'adequate' ? 'yellow' : 'red';
    protoTable.push(
      [formatField('Cipher', c.name)],
      [formatField('Strength', `${c.bits}-bit (${chalk[strengthColor](c.strength)})`)]
    );
  }

  if (report.protocol.recommendations.length > 0) {
    protoTable.push([
      chalk.yellow('Recommendations: ') +
        report.protocol.recommendations.join('; '),
    ]);
  }

  output.push(protoTable.toString());

  // Chain
  if (report.chain.length > 0) {
    const chainTable = new Table({
      head: [
        chalk.bold('#'),
        chalk.bold('Type'),
        chalk.bold('Subject'),
        chalk.bold('Expires'),
      ],
      colWidths: [5, 15, 40, 20],
      style: { head: [], border: ['gray'] },
    });

    for (let i = 0; i < report.chain.certificates.length; i++) {
      const cert = report.chain.certificates[i];
      const expColor = cert.expiry.isExpired
        ? 'red'
        : cert.expiry.isExpiringSoon
          ? 'yellow'
          : 'green';
      chainTable.push([
        String(i + 1),
        cert.label,
        truncate(cert.subject, 38),
        chalk[expColor](`${cert.expiry.daysRemaining}d`),
      ]);
    }
    output.push(chainTable.toString());
  }

  // OCSP
  const ocspLine = formatOCSP(report.ocsp);
  output.push(`\n  OCSP Status: ${ocspLine}`);

  // Trust
  const trustLine = report.authorized
    ? chalk.green('✔ Certificate is trusted')
    : chalk.red(`✖ Not trusted: ${report.authorizationError}`);
  output.push(`  Trust: ${trustLine}`);

  // Warnings
  if (report.warnings.length > 0) {
    output.push('');
    output.push(chalk.yellow.bold('  Warnings:'));
    for (const w of report.warnings) {
      output.push(chalk.yellow(`    ⚠ ${w}`));
    }
  }

  output.push('');
  return output.join('\n');
}

/**
 * Format report as JSON (pretty-printed).
 */
function formatJSON(report) {
  return JSON.stringify(report, null, 2);
}

/**
 * Format multiple reports.
 */
function formatReports(reports, format) {
  if (format === 'json') {
    return reports.length === 1
      ? formatJSON(reports[0])
      : JSON.stringify(reports, null, 2);
  }

  return reports.map((r) => formatTable(r)).join('\n' + chalk.gray('─'.repeat(80)) + '\n');
}

function formatField(label, value) {
  return `${chalk.gray(label + ':')} ${value || chalk.gray('N/A')}`;
}

function formatDate(isoString) {
  if (!isoString) return 'N/A';
  const d = new Date(isoString);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

function formatOCSP(status) {
  switch (status) {
    case 'good':
      return chalk.green('✔ Good');
    case 'revoked':
      return chalk.red('✖ REVOKED');
    case 'unknown':
      return chalk.yellow('? Unknown');
    default:
      return chalk.gray('— Not available');
  }
}

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

module.exports = {
  formatTable,
  formatJSON,
  formatReports,
};
