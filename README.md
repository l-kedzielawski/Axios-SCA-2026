# Axios npm Supply Chain Attack — Detection & Protection Guide

> **Incident date:** March 31, 2026 | **Severity:** Critical | **Status:** Malicious versions removed from npm

A supply chain attack compromised the official `axios` npm package — one of the most widely used JavaScript libraries, with ~100 million weekly downloads. Two malicious versions were live on the registry for approximately 3 hours. This guide covers what happened, how to check if you are affected, and how to protect yourself going forward.

---

## Table of Contents

- [What Happened](#what-happened)
- [Am I Affected?](#am-i-affected)
- [Indicators of Compromise (IoCs)](#indicators-of-compromise-iocs)
- [Immediate Response Steps](#immediate-response-steps)
- [Detection Scripts](#detection-scripts)
- [Hardening Your npm Workflow](#hardening-your-npm-workflow)
- [Why `npm audit` Will Not Help You Here](#why-npm-audit-will-not-help-you-here)
- [Resources](#resources)

---

## What Happened

### Attack Timeline

| Time (UTC) | Event |
|---|---|
| Mar 30 — 05:57 | Attacker publishes `plain-crypto-js@4.2.0` (clean decoy) to pre-stage name in registry |
| Mar 30 — 23:59 | Attacker publishes `plain-crypto-js@4.2.1` with malicious `postinstall` hook |
| Mar 31 — 00:21 | Malicious `axios@1.14.1` published via compromised maintainer account |
| Mar 31 — 01:00 | Malicious `axios@0.30.4` published via same account |
| Mar 31 — 03:29 | Both malicious versions removed from npm by registry |

### How It Worked

1. **Account takeover.** The attacker compromised the npm account of `jasonsaayman`, the primary Axios maintainer, likely by stealing a long-lived classic npm access token. They changed the account's registered email to `ifstap@proton.me`, locking the legitimate owner out of recovery flows.

2. **Dependency injection.** The only change to Axios in both poisoned versions was a single line added to `package.json`:
   ```json
   "dependencies": {
     "plain-crypto-js": "4.2.1"
   }
   ```
   The real Axios has only three dependencies: `follow-redirects`, `form-data`, and `proxy-from-env`. `plain-crypto-js` is not one of them.

3. **Postinstall execution.** When npm resolved the dependency tree, it automatically installed `plain-crypto-js@4.2.1` and ran its `postinstall` script (`node setup.js`). This dropper contacted a live C2 server at `sfrclak.com:8000` and downloaded platform-specific second-stage payloads.

4. **RAT deployment.** The second-stage payload is a cross-platform Remote Access Trojan (RAT) targeting Windows, macOS, and Linux. Capabilities include remote shell execution, directory browsing, process listing, file exfiltration, and system reconnaissance. It beacons to the C2 every 60 seconds.

5. **Self-deletion.** After executing, the dropper deleted itself and replaced `node_modules/plain-crypto-js/package.json` with a clean decoy — leaving no visible trace in `node_modules`.

> **The infection path is the install/build step, not app runtime.** End users loading your app in a browser are not directly affected. Developers and CI/CD pipelines that ran `npm install` during the window are the target.

---

## Am I Affected?

You are **at risk** if you ran `npm install` (or `npm update`) between approximately **00:21 UTC and 03:29 UTC on March 31, 2026**, AND your project resolved to one of:

- `axios@1.14.1`
- `axios@0.30.4`

Projects using caret ranges like `^1.14.0` or `^0.30.0` would have automatically pulled in the compromised version on a fresh install.

You are also at risk if your project directly depends on:

- `@shadanai/openclaw` (versions `2026.3.28-2`, `2026.3.28-3`, `2026.3.31-1`, `2026.3.31-2`)
- `@qqbrowser/openclaw-qbot@0.0.130`

These packages ship a vendored tampered copy of `axios@1.14.1`.

You were **not affected** if:

- Your `package-lock.json` or `yarn.lock` was committed before the malicious versions were published **and** your install did not update it (i.e., you use `npm ci`)
- Your axios version was pinned to anything other than `1.14.1` or `0.30.4`
- You did not run any npm install during the 3-hour window

---

## Indicators of Compromise (IoCs)

### Malicious packages

| Package | Version |
|---|---|
| `axios` | `1.14.1` |
| `axios` | `0.30.4` |
| `plain-crypto-js` | `4.2.1` |
| `@shadanai/openclaw` | `2026.3.28-2`, `2026.3.28-3`, `2026.3.31-1`, `2026.3.31-2` |
| `@qqbrowser/openclaw-qbot` | `0.0.130` |

### Network indicators

| Indicator | Type |
|---|---|
| `sfrclak.com` | C2 domain |
| `sfrclak.com:8000` | C2 address (dropper callback and RAT beacon) |
| HTTP POST beacons every 60 seconds to C2 | Behaviour |

### npm account indicators

| Indicator | Value |
|---|---|
| Compromised maintainer account | `jasonsaayman` |
| Attacker-controlled email (axios account) | `ifstap@proton.me` |
| Malicious package publisher | `nrwise` |
| Attacker-controlled email (plain-crypto-js) | `nrwise@proton.me` |

---

## Immediate Response Steps

### Step 1 — Check your installed axios version

```bash
# In your project directory
npm list axios

# Or check your lockfile directly
grep '"axios"' package-lock.json | head -5
grep 'axios' yarn.lock | head -5
```

If you see `1.14.1` or `0.30.4` anywhere, proceed to Step 2.

### Step 2 — Check for the malicious dependency

```bash
# Check if plain-crypto-js was ever installed
npm list plain-crypto-js

# Check npm install logs (macOS/Linux)
grep -r "plain-crypto-js" ~/.npm/_logs/ 2>/dev/null

# Check npm cache
ls ~/.npm/plain-crypto-js/ 2>/dev/null
```

### Step 3 — Check CI/CD logs

Search your CI pipeline logs for the window **00:21 to 03:29 UTC on March 31, 2026** for:

- Any `npm install` or `npm update` runs
- References to `plain-crypto-js`
- Outbound connections to `sfrclak.com`

### Step 4 — Check for network indicators

```bash
# Check DNS resolution (confirms C2 domain was ever contacted)
# macOS
log show --predicate 'process == "mDNSResponder" && eventMessage contains "sfrclak"' --last 48h

# Linux — check systemd-resolved or dnsmasq logs
journalctl -u systemd-resolved | grep sfrclak

# Check for active connections
netstat -an | grep sfrclak
ss -tuln | grep 8000

# Search firewall / proxy logs
grep "sfrclak" /var/log/nginx/access.log 2>/dev/null
grep "sfrclak" /var/log/ufw.log 2>/dev/null
```

### Step 5 — If you confirm execution, treat the machine as fully compromised

- **Isolate the machine** from the network immediately
- **Rotate all secrets** reachable from that machine:
  - npm tokens
  - SSH keys
  - Cloud provider credentials (AWS, GCP, Azure)
  - API keys stored in `.env` files or CI secrets
  - GitHub/GitLab deploy keys and personal access tokens
  - Database credentials
- **Audit access logs** on any services the machine had credentials for
- **Review git history** of any repos the machine had write access to for unexpected commits
- **Reinstall the OS** if the machine is a developer workstation — do not trust it after RAT execution

---

## Detection Scripts

### Quick check (Bash — Linux/macOS) ./scripts/

Run it with:

```bash
chmod +x axios-sca-check.sh
./axios-sca-check.sh
# or from a specific project dir:
cd /your/project && ~/axios-sca-2026/check.sh
```

### Node.js check (cross-platform) ./scripts/

```bash
node check.mjs              # current directory
node check.mjs /path/to/project  # specific project
```

---

## Hardening Your npm Workflow

### 1. Always use `npm ci` in CI/CD, never `npm install`

`npm ci` enforces lockfile integrity. It will fail if `package-lock.json` is out of date, preventing surprise version resolution.

```yaml
# GitHub Actions
- name: Install dependencies
  run: npm ci
```

### 2. Pin exact versions in `package.json`

Caret (`^`) and tilde (`~`) ranges automatically resolve to the latest matching version on install. Pinning eliminates this risk.

```json
{
  "dependencies": {
    "axios": "1.7.9"
  }
}
```

### 3. Disable postinstall scripts in CI where not needed

```bash
npm ci --ignore-scripts
```

This would have fully blocked this attack. Note that some packages require postinstall scripts for native addons — test carefully before enforcing globally.

### 4. Commit and protect your lockfile

Your `package-lock.json` or `yarn.lock` must be committed to version control and treated as a security artifact. Add a CI check that fails if the lockfile is modified:

```yaml
# GitHub Actions
- name: Verify lockfile integrity
  run: |
    npm ci
    git diff --exit-code package-lock.json
```

### 5. Block suspicious packages at the registry level

Add `plain-crypto-js` and similar known-malicious packages to your organization's npm blocklist or to your Artifactory/Nexus allowlist policy.

### 6. Audit `postinstall` scripts before they run

Use `npq` to interactively inspect packages before installation:

```bash
npx npq install axios
```

Or use `socket` CLI for dependency analysis:

```bash
npx @socket-security/cli scan
```

### 7. Monitor outbound network connections from build environments

Runtime monitoring (e.g., StepSecurity Harden-Runner for GitHub Actions, Falco for containers) can detect unexpected outbound connections to C2 infrastructure during CI runs — even if the malicious package self-deletes before you check `node_modules`.

### 8. Enforce npm token rotation and 2FA on all publishing accounts

This attack succeeded because the attacker obtained a long-lived classic npm token. Enforce:

- Granular publish tokens scoped to specific packages with short TTLs
- 2FA required for all accounts with publish permissions
- Trusted publishing via GitHub Actions OIDC (no stored tokens at all)

### 9. Use a private registry or allowlist mirror

Routing installs through an Artifactory or Verdaccio instance gives you a checkpoint to scan packages before they reach developers.

---

## Why `npm audit` Will Not Help You Here

> **`npm audit` will NOT detect this attack after the fact.**

The malicious dropper (`setup.js`) self-deletes after executing and replaces `node_modules/plain-crypto-js/package.json` with a clean decoy. After execution, `node_modules` will look completely normal. `npm audit` inspects the current state of installed packages against known advisory databases — it cannot detect:

- A package that was installed and self-deleted
- Post-execution persistence payloads running outside `node_modules`
- Network connections already made to C2

**The only reliable post-incident indicators are:**

- Lockfile contents showing the malicious versions were resolved
- CI log timestamps overlapping with the attack window
- Network logs showing connections to `sfrclak.com:8000`
- Active RAT processes (second-stage payload survives the dropper self-deletion)

---

## Resources

| Source | Link |
|---|---|
| Snyk analysis | https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/ |
| StepSecurity full technical breakdown | https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan |
| Wiz impact assessment | https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack |
| Socket.dev analysis | https://socket.dev/blog/axios-npm-package-compromised |
| Picus Security attack chain | https://www.picussecurity.com/resource/blog/axios-npm-supply-chain-attack-cross-platform-rat-delivery-via-compromised-maintainer-credentials |
| Help Net Security | https://www.helpnetsecurity.com/2026/03/31/axios-npm-backdoored-supply-chain-attack/ |
| The Hacker News | https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html |
| Malwarebytes | https://www.malwarebytes.com/blog/news/2026/03/axios-supply-chain-attack-chops-away-at-npm-trust |
| GitHub advisory | https://github.com/advisories/GHSA-fw8c-xr5c-95f9 |
| Official Axios GitHub issue | https://github.com/axios/axios/issues/ |

---

## License

MIT — use freely, share widely.

## Contact

Lukasz Kedzielawski
l.kedzielawski@gmail.com

---

*Last updated: March 31, 2026. This is a rapidly evolving incident. Check linked sources for the latest details.*
