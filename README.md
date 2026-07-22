# Scan Compromised

🔍 A CLI tool to detect known compromised npm packages in your project.

**No third-party dependencies:** This tool is fully self-contained and does not rely on any external npm packages or libraries. You can use it with confidence in sensitive or locked-down environments.

This scanner checks your `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files for any packages that were compromised in recent supply chain attacks — including the September 2024 XZ Utils backdoor and other known malicious releases.

It flags:
- ❌ Known malicious versions (fails the scan)
- ⚠️ Safe versions of previously compromised packages (warns but does not fail)

---

## 📋 Table of Contents

- [Installation](#-installation)
- [Usage](#-usage)
- [Output Examples](#-output-examples)
- [Threat List & Data Updates](#-threat-list--data-updates)
- [GitHub Actions Integration](#-github-actions-integration)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## 🚀 Installation

### Recommended: Run directly with `npx` (no install)
```bash
npx scan-compromised
```

### Or install globally
```bash
npm install -g scan-compromised
scan-compromised
```

---

## 📦 Usage

### Basic scan
```bash
scan-compromised
```

### Hard gate: block installs with known advisories

Add this to your project's `preinstall` script in `package.json`:
```json
"scripts": {
  "preinstall": "npx scan-compromised"
}
```

⚠️ **Note:** The `preinstall` script runs *before* `npm install`. If the scan detects known malicious packages, it will exit with a non-zero code and **halt the installation**, acting as a hard gate in your supply chain.

### JSON output (for CI integration)
```bash
scan-compromised --json
```

---

## 📊 Output Examples

### Standard output
```
✓ Scanning package.json...
✓ No known compromised packages detected
Scan completed successfully
```

### With threats detected
```
✗ Scanning package.json...
⚠️ ngx-toastr@19.0.1 is a known compromised package
✗ Scan failed: malicious version detected
```

### JSON output
```json
{
  "success": false,
  "threats": [
    {
      "package": "ngx-toastr",
      "version": "19.0.1",
      "severity": "critical"
    }
  ],
  "timestamp": "2026-07-22T12:00:00Z"
}
```

---

## 📁 Threat List & Data Updates

The tool uses a local `threats.json` file located in the root of the CLI package. This file contains a list of known compromised packages and their malicious versions.

### Data Sources

The threat database is built from trusted security advisories:

- **[GitHub Security Advisories](https://github.com/advisories)** — Official vulnerability reports
- **[Snyk Vulnerability Database](https://snyk.io/vulnerability-scanner/)** — Comprehensive threat intelligence
- **[StepSecurity](https://www.stepsecurity.io/)** — Supply chain security data

### Update Frequency

The threat list is updated when new versions of the `scan-compromised` package are published. To get the latest threats:

```bash
npm update -g scan-compromised
```

Or if using `npx`, it will automatically fetch the latest version on each run.

### Manual updates

You can update `threats.json` manually as new threats are discovered:

```json
{
  "@ctrl/tinycolor": ["4.1.1", "4.1.2"],
  "ngx-toastr": ["19.0.1", "19.0.2"],
  "malicious-pkg": ["1.0.0"]
}
```

---

## 🧪 GitHub Actions Integration

You can run this tool automatically on every push or pull request using GitHub Actions.

**`.github/workflows/scan.yml`**

```yaml
name: Scan for Compromised Packages

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Run compromised package scan
        run: npx scan-compromised --json
```

This will block merges if malicious packages are detected.

---

## 🔧 Troubleshooting

### No packages found

If the scanner doesn't detect any lock files, ensure you have one of the following in your project root:
- `package.json`
- `package-lock.json`
- `yarn.lock`
- `pnpm-lock.yaml`

### Monorepo or workspace support

For monorepos, run the scanner from the root directory. It will scan all workspace packages.

### Exit codes

- `0` — Scan successful, no threats detected
- `1` — Scan detected known malicious packages
- `2` — Scanner error (missing files, invalid JSON, etc.)

### False positives

If you believe a detection is a false positive, please [open an issue](https://github.com/bladeski/scan-compromised/issues) with details about the package and version.

---

## 🛡️ License

MIT © Jonathan Blades (jonoblades@gmail.com)
