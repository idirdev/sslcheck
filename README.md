# sslcheck

**[EN]** A powerful CLI tool to inspect and analyze SSL/TLS certificates for any domain.
**[FR]** Un outil CLI puissant pour inspecter et analyser les certificats SSL/TLS de n'importe quel domaine.

---

## Features / Fonctionnalites

**[EN]**
- Full certificate details: subject, issuer, serial number, fingerprints
- Validity analysis with expiry warnings (< 30 days) and critical alerts (< 7 days)
- Subject Alternative Names (SANs) listing
- TLS protocol version and cipher suite analysis with security grading (A+ to F)
- Complete certificate chain inspection
- OCSP revocation status check
- Multiple domains in a single command
- Table or JSON output formats
- Color-coded output for quick visual assessment
- Exit codes for CI/CD integration (0 = OK, 1 = warnings, 2 = errors/expired)

**[FR]**
- Details complets du certificat : sujet, emetteur, numero de serie, empreintes
- Analyse de validite avec alertes d'expiration (< 30 jours) et alertes critiques (< 7 jours)
- Liste des Subject Alternative Names (SANs)
- Analyse du protocole TLS et de la suite de chiffrement avec notation de securite (A+ a F)
- Inspection complete de la chaine de certificats
- Verification du statut de revocation OCSP
- Verification de plusieurs domaines en une seule commande
- Formats de sortie : tableau ou JSON
- Sortie coloree pour une evaluation visuelle rapide
- Codes de sortie pour integration CI/CD (0 = OK, 1 = alertes, 2 = erreurs/expire)

---

## Installation

```bash
# Global install / Installation globale
npm install -g sslcheck

# Or use npx / Ou utiliser npx
npx sslcheck google.com
```

---

## Usage / Utilisation

### Basic check / Verification basique

```bash
sslcheck google.com
```

### Multiple domains / Plusieurs domaines

```bash
sslcheck google.com github.com mozilla.org
```

### JSON output / Sortie JSON

```bash
sslcheck google.com --json
```

### Custom port / Port personnalise

```bash
sslcheck myserver.com:8443
```

### Custom timeout / Timeout personnalise

```bash
sslcheck google.com --timeout 5000
```

### Skip OCSP check / Ignorer la verification OCSP

```bash
sslcheck google.com --no-ocsp
```

### Full options / Toutes les options

```bash
sslcheck --help
```

```
Usage: sslcheck [options] <domains...>

Inspect and analyze SSL/TLS certificates for any domain

Arguments:
  domains                One or more domains to check (e.g. example.com google.com:443)

Options:
  -v, --version          output the version number
  -j, --json             Output results as JSON (default: false)
  -t, --timeout <ms>     Connection timeout in milliseconds (default: 10000)
  --no-ocsp              Skip OCSP status check
  --no-color             Disable colored output
  -c, --concurrency <n>  Max concurrent checks (default: 5)
  -h, --help             display help for command
```

---

## Programmatic API / API programmatique

**[EN]** You can also use sslcheck as a library in your Node.js projects.
**[FR]** Vous pouvez aussi utiliser sslcheck comme bibliotheque dans vos projets Node.js.

```javascript
const { check, checkMultiple } = require('sslcheck');

// Single domain / Domaine unique
const report = await check('google.com');
console.log(report.grade);                // "A+"
console.log(report.expiry.daysRemaining); // 85
console.log(report.warnings);             // []

// Multiple domains / Plusieurs domaines
const reports = await checkMultiple(['google.com', 'github.com'], {
  timeout: 5000,
  skipOCSP: true,
  concurrency: 3,
});
```

### Report object / Objet rapport

```javascript
{
  host: 'google.com',
  port: 443,
  grade: 'A+',               // A+, A, B, C, F
  authorized: true,           // OS trust store validation
  certificate: {
    subject: 'CN=*.google.com',
    issuer: 'CN=GTS CA 1C3, O=Google Trust Services LLC',
    serialNumber: '...',
    fingerprints: { sha1: '...', sha256: '...' }
  },
  expiry: {
    validFrom: '2026-01-01T00:00:00.000Z',
    validTo: '2026-06-01T00:00:00.000Z',
    daysRemaining: 78,
    status: 'valid',          // valid, warning, critical, expired, not_yet_valid
    isExpired: false,
    isExpiringSoon: false
  },
  sans: {
    dns: ['*.google.com', 'google.com'],
    ip: [],
    count: 2
  },
  protocol: {
    version: 'TLSv1.3',
    grade: 'A+',
    isSecure: true,
    cipher: { name: 'TLS_AES_256_GCM_SHA384', bits: 256, strength: 'strong' }
  },
  chain: {
    length: 3,
    valid: true,
    certificates: [...]
  },
  ocsp: 'good',              // good, revoked, unknown, unavailable
  warnings: []
}
```

---

## Exit codes / Codes de sortie

| Code | EN | FR |
|------|----|----|
| `0` | All certificates valid, no warnings | Tous les certificats valides, aucune alerte |
| `1` | Valid but with warnings (expiring soon, etc.) | Valide mais avec alertes (expiration proche, etc.) |
| `2` | Errors or expired certificates | Erreurs ou certificats expires |

---

## Tests

```bash
npm test
```

---

## License

MIT - idirdev

---

## Author / Auteur

**idirdev**
