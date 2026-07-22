# Scan Compromised

🔍 A CLI tool to detect known compromised npm packages in your project.

**No third-party dependencies:** This tool is fully self-contained and does not rely on any external npm packages or libraries. You can use it with confidence in sensitive or locked-down environments.

This scanner checks your `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files for any packages that were compromised in recent supply chain attacks — including the September 2024 incident and other known exploits.

It flags:
- ❌ Known malicious versions (fails the scan)
- ⚠️ Safe versions of previously compromised packages (warns but does not fail)

---

## ✨ Features

- **Zero dependencies** — No external npm packages required
- **Multiple lock file support** — Scans package-lock.json, yarn.lock, pnpm-lock.yaml, and package.json
- **Fast local scanning** — No network calls needed for threat detection
- **CI/CD ready** — JSON output and exit codes for easy integration
- **GitHub Actions support** — Pre-configured workflow examples included
- **Hard gate capability** — Block installations with malicious packages

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Examples](#-output-examples)
- [Threat List & Data Updates](#-threat-list--data-updates)
- [GitHub Actions Integration](#-github-actions-integration)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ⚡ Quick Start

Get started in seconds:

```bash
npx scan-compromised
```

That's it! The tool will scan your project and report any known compromised packages.

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

### Requirements

- **Node.js:** 14.0.0 or higher
- **npm:** 6.0.0 or higher (or Yarn/pnpm equivalent)

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

⚠️ **Note:** The `preinstall` script runs *before* `npm install`. If the scan detects known malicious packages, it will exit with a non-zero code and **halt the installation**, acting as a hard gate.

### JSON output (for CI integration)
```bash
scan-compromised --json
```

---

## 📊 Output Examples

### Standard output (no threats)
```
✓ Scanning package.json...
✓ No known compromised packages detected
Scan completed successfully
```

### Standard output (with threats detected)
```
✗ Scanning package.json...
✗ ngx-toastr@19.0.1 — CRITICAL: Known malicious package
✗ Scan failed: 1 malicious package detected
```

### JSON output
```json
{
  "success": false,
  "threats": [
    {
      "package": "ngx-toastr",
      "version": "19.0.1",
      "severity": "critical",
      "type": "malicious"
    }
  ],
  "count": 1,
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

### Database Information

- **Current tracked packages:** 50+
- **Total monitored versions:** 200+
- **Last updated:** With every package release
- **View the database:** [`threats.json`](./threats.json)

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

### Basic workflow

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

### With branch protection

To prevent merges when malicious packages are detected, add this workflow as a required status check in your [branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches):

1. Go to **Settings** → **Branches**
2. Add branch protection rule for `main`
3. Enable **Require status checks to pass before merging**
4. Select the **Scan for Compromised Packages** check

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

If you believe a detection is a false positive, please [open an issue](https://github.com/bladeski/scan-compromised/issues) with:
- Package name and version
- Details about why you believe it's a false positive
- Any additional context

---

## 🤝 Contributing

Contributions are welcome! If you've discovered a new compromised package or have improvements to suggest:

1. [Open an issue](https://github.com/bladeski/scan-compromised/issues) to discuss the change
2. [Submit a pull request](https://github.com/bladeski/scan-compromised/pulls) with your updates to `threats.json` or code
3. Ensure your threat data includes the package name, affected versions, and source

### Threat data contributions

When submitting a threat update, please include:
- Package name (exact npm package name)
- Affected version(s)
- Source/advisory link
- Brief description of the threat

---

## 🛡️ License

MIT © Jonathan Blades (jonoblades@gmail.com)
