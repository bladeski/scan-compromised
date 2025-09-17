# scan-compromised

🔍 A CLI tool to detect known compromised npm packages in your project.

This scanner checks your `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files for any packages that were compromised in recent supply chain attacks — including the September 2025 Shai-Hulud incident.

It flags:
- ❌ Known malicious versions (fails the scan)
- ⚠️ Safe versions of previously compromised packages (warns but does not fail)

---

## 🚀 Installation

### Run directly with `npx` (no install)
```bash
npx scan-compromised
```
Or install globally
```bash
npm install -g scan-compromised
scan-compromised
```
## 📦 Usage
### Basic scan
```bash
scan-compromised
```
### JSON output (for CI integration)
```bash
scan-compromised --json
```
## 📁 Threat List
The tool uses a local `threats.json` file located in the root of the CLI package. This file contains a list of known compromised packages and their malicious versions.

Example `threats.json`
```json
{
  "@ctrl/tinycolor": ["4.1.1", "4.1.2"],
  "ngx-toastr": ["19.0.1", "19.0.2"]
}
```
You can update this file manually as new threats are discovered. Trusted sources include:

StepSecurity

GitHub Security Advisories

Snyk Vulnerability Database

## 🧪 GitHub Actions Integration
You can run this tool automatically on every push or pull request using GitHub Actions.

`.github/workflows/scan.yml`
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
      - name: Install scanner
        run: npm install scan-compromised
      - name: Run scan
        run: npx scan-compromised
```
## 🛡️ License
MIT © Jonathan Blades