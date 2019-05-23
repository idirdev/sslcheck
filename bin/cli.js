#!/usr/bin/env node
'use strict';

/**
 * @fileoverview CLI for sslcheck — check SSL/TLS certificates on remote domains.
 * @author idirdev
 */

const { checkCert, checkMultiple, formatReport, formatTable, summary } = require('../src/index');

const args = process.argv.slice(2);

/**
 * Parse a named argument value from the argv array.
 * @param {string[]} argv - Array of CLI arguments.
 * @param {string}   flag - Flag (e.g. "--port").
 * @param {*}        def  - Default value.
 * @returns {string|*}
 */
function getArg(argv, flag, def) {
  const i = argv.indexOf(flag);
  return i !== -1 && argv[i + 1] !== undefined ? argv[i + 1] : def;
}

// Collect positional domain arguments (everything not starting with --)
const domains = args.filter((a, i) => {
  if (!a.startsWith('-')) {
    // Skip values that follow a flag
    if (i > 0 && args[i - 1].startsWith('--')) return false;
    return true;
  }
  return false;
});

if (domains.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log([
    '',
    'Usage: sslcheck <domain...> [options]',
    '',
    'Arguments:',
    '  domain          One or more domains to check (e.g. example.com google.com:8443)',
    '',
    'Options:',
    '  --port <n>      Default port (default: 443)',
    '  --json          Output as JSON',
    '  --table         Output as formatted table',
    '  --warn-days <n> Days threshold for expiry warning (default: 30)',
    '',
    'Examples:',
    '  sslcheck example.com',
    '  sslcheck example.com github.com --table',
    '  sslcheck example.com --json',
    '',
  ].join('\n'));
  process.exit(0);
}

const port = parseInt(getArg(args, '--port', '443'), 10);
const warnDays = parseInt(getArg(args, '--warn-days', '30'), 10);
const asJSON = args.includes('--json');
const asTable = args.includes('--table');

(async () => {
  try {
    let results;
    if (domains.length === 1) {
      const info = await checkCert(domains[0], port);
      results = [info];
    } else {
      results = await checkMultiple(domains, port);
    }

    if (asJSON) {
      console.log(JSON.stringify(results.length === 1 ? results[0] : results, null, 2));
    } else if (asTable) {
      process.stdout.write(formatTable(results));
    } else {
      for (const info of results) {
        process.stdout.write(formatReport(info));
        if (results.length > 1) process.stdout.write('\n');
      }
    }

    const s = summary(results);
    if (s.errors > 0 || s.expired > 0) process.exit(2);
    if (s.expiringSoon > 0) process.exit(1);
    process.exit(0);
  } catch (err) {
    console.error('Fatal: ' + err.message);
    process.exit(2);
  }
})();
