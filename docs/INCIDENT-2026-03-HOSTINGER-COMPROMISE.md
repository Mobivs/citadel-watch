# Incident Report: Hostinger Account-Level Compromise
**Date Discovered:** 2026-03-06
**Severity:** Critical
**Status:** Active / Containment In Progress
**Affected Systems:** Hostinger hPanel account, shared PHP hosting, VPS instances, API tokens

---

## Executive Summary

A full account-level compromise of the Hostinger hosting account was discovered in early March 2026. The attacker obtained access to the hPanel control panel itself — not just an individual application or server — giving them administrative control over all hosted services including VPS instances, shared PHP sites, SSH key management, database credentials, and API tokens. The attack is sophisticated, persistent, and shows signs of extended dwell time (weeks to months).

---

## Symptoms Observed (Chronological)

### 1. Database Passwords Repeatedly Changed
- PHP application database passwords kept being reset without user action
- Attacker used hPanel database management to lock out legitimate applications while maintaining their own access
- Pattern: credentials reset after user restores them — indicates active, ongoing attacker presence

### 2. Unauthorized SSH Keys Appeared
- SSH keys the user never created began appearing in hPanel SSH key management
- Attacker added their own public keys to `~/.ssh/authorized_keys` on VPS instances
- Provides persistent shell access that survives password resets

### 3. SSH Key Naming Behavior Changed
- Previously, users could name SSH keys freely upon adding them
- Changed to: keys are auto-assigned a hash of the public key as the name, and the name is not editable
- This is consistent with hPanel platform-level tampering or the attacker modifying the interface behavior
- Possibly a Hostinger-side platform change in response to the December 2025 breach, or attacker-controlled behavior

### 4. Browser Terminal Behavior Degraded
- hPanel browser terminal began requiring login on every session (previously persisted)
- Started prompting for passwords unexpectedly mid-session
- Consistent with session invalidation or a malicious PAM module being inserted into the auth stack

### 5. Terminal Bracketed Paste Injection (`^[[200~` ... `~`)
- Copy-pasting into the browser terminal prepended `^[[200~` and appended `~` to all pasted content
- This is the ANSI escape sequence for **bracketed paste mode** (`ESC[?2004h`)
- **Root cause**: Shell configuration files (`.bashrc`, `.bash_profile`, or `/etc/profile.d/` scripts) were poisoned with `printf '\e[?2004h'` to enable bracketed paste mode on every login
- This is a documented attacker technique (see MITRE ATT&CK T1546.004) to make the terminal appear broken, frustrating the legitimate user while backdoors continue to operate
- The cursor mid-row line jumping is the same escape sequence corruption affecting readline/terminal state

### 6. Terminal Became Completely Unusable
- Backspace could delete over the `username@servername:` prompt
- Cursor auto-jumped to a new line in the middle of a row
- Eventually the terminal was entirely inoperable
- Attacker's goal: deny legitimate user terminal access while maintaining their own SSH backdoor

### 7. Recon Traffic to PHP Sites
- The same small set of server IPs began hitting all PHP sites daily
- Pattern: direct URL access (no referrer), single page hit per visit, no navigation to second pages, repeated daily
- **Root cause**: These are C2 (command-and-control) beacon checks from webshells planted in the PHP sites
- The attacker's botnet pings each planted webshell daily to confirm it is still alive and reachable
- Consistent with cross-contamination on shared hosting — once one site is compromised, the attacker pivots to all others on the same account

### 8. Hostinger API Keys Stopped Working
- Existing API tokens generated through hPanel stopped authenticating
- Either: (a) attacker rotated/revoked tokens to cut off the user's tooling (Citadel Archer), or (b) Hostinger security suspended tokens due to anomalous usage patterns detected during the breach

---

## Technical Analysis

### Attack Vector Assessment

**Most Likely: Hostinger Platform-Level Breach (December 2025)**
- Hostinger disclosed a shared hosting breach in December 2025
- The breadth of access (SSH keys, database passwords, API tokens, hPanel sessions, terminal behavior) is consistent with platform-level compromise, not a single application exploit
- An attacker with access to Hostinger's internal systems could modify hPanel behavior, inject into browser terminal sessions, and access credentials stored in the platform

**Secondary Vector: Google OAuth Session Compromise**
- The user authenticates to Hostinger via Google OAuth — there is no separate Hostinger password
- If the Google account was compromised (phishing, credential stuffing, malicious OAuth app), the attacker would have full hPanel access via Google sign-in
- The account-level access is consistent with either a stolen Google session cookie or a compromised Google account

**Confirmed Techniques Used**
| Technique | MITRE ATT&CK | Evidence |
|---|---|---|
| Account Manipulation: SSH Authorized Keys | T1098.004 | Unauthorized keys in hPanel and authorized_keys |
| Unix Shell Configuration Modification | T1546.004 | Bracketed paste injection via .bashrc/.profile |
| Web Shell | T1505.003 | Daily C2 beacon traffic to PHP sites from fixed IPs |
| Valid Accounts | T1078 | hPanel access without triggering lockout |
| Data from Local System | T1005 | Database credential harvesting |
| Cross-Site Contamination | - | All PHP sites hit from same attacker IPs after single initial compromise |

### Citadel Archer Exposure

This incident has direct implications for the Citadel Archer project:

1. **Hostinger API Token Stolen** — `data/user_preferences.db` stores the API key in plaintext. If any VPS was compromised, this file was readable by the attacker.
2. **VPS SSH Keys Compromised** — SSH credentials stored in `data/vault.db` and used by `ssh_manager.py` may be known to the attacker.
3. **Tailscale Network Exposure** — If the VPS (Tailscale IP 100.87.127.46) is compromised, the attacker has a node on our Tailscale network with access to 100.68.75.8 (home machine).
4. **Citadel Daemon Integrity Unknown** — The `citadel-daemon` service running on VPS instances may be on a compromised host. Reports from these agents cannot be trusted until hosts are rebuilt.
5. **Machine Key / Vault Encryption** — `data/machine.key` and `data/auto_unlock.enc` provide access to vault-encrypted secrets. These files must be considered compromised on any affected VPS.

---

## Containment Steps (Ordered by Priority)

### Immediate (Do First)
- [ ] Secure Google account: change password from a clean device
- [ ] Enable Google 2FA (hardware key preferred over SMS)
- [ ] Check Google "Your devices" — revoke all unrecognized sessions
- [ ] Check Google "Third-party apps" (`myaccount.google.com/permissions`) — revoke suspicious OAuth grants
- [ ] Check Google "Ways we can verify it's you" — remove any unfamiliar recovery phone/email
- [ ] Log back into Hostinger fresh, terminate all active hPanel sessions
- [ ] Revoke ALL Hostinger API tokens — generate a new one

### VPS Remediation (Per Instance)
- [ ] Audit `~/.ssh/authorized_keys` and `/root/.ssh/authorized_keys` — remove all keys you did not add
- [ ] Inspect shell startup files for bracketed paste injection:
  ```bash
  grep -E '(printf|\\033|\\e\[|2004)' ~/.bashrc ~/.bash_profile /etc/profile /etc/profile.d/*
  ```
- [ ] Check for new user accounts: `cat /etc/passwd | grep -v nologin | grep -v false`
- [ ] Audit cron jobs: `crontab -l && cat /etc/cron.d/* && ls /var/spool/cron/`
- [ ] Check for new/modified systemd services:
  ```bash
  find /etc/systemd/system -newer /etc/hostname -name "*.service"
  systemctl list-units --state=failed
  ```
- [ ] Review running processes for unknown services: `ps auxf`
- [ ] Check listening ports: `ss -tlnp`
- [ ] Consider full VPS rebuild if compromise confirmed — a rootkitted server cannot be trusted

### PHP Shared Hosting
- [ ] Find recently modified PHP files:
  ```bash
  find /public_html -name "*.php" -newer /public_html/index.php -ls
  ```
- [ ] Scan for base64-encoded payloads (common webshell obfuscation):
  ```bash
  grep -rl "base64_decode" /public_html --include="*.php"
  grep -rl "eval(" /public_html --include="*.php"
  ```
- [ ] Block the recon/beacon IPs at the Hostinger firewall
- [ ] Change all database passwords after webshells are removed (not before — need to investigate)
- [ ] Request Hostinger malware scan on shared hosting account

### Citadel Archer Specific
- [ ] Rotate Hostinger API token in `data/user_preferences.db` after account is secured
- [ ] Rotate all VPS SSH credentials stored in vault
- [ ] Regenerate `data/machine.key` and re-encrypt vault (this requires a new vault setup)
- [ ] Remove compromised VPS agents from Citadel Archer asset registry until hosts are rebuilt
- [ ] Do NOT trust threat reports from VPS daemons until hosts are verified clean

### Contact Hostinger Support
- Reference the December 2025 shared hosting breach
- Request: account audit log (IP addresses and timestamps of all hPanel logins)
- Request: confirmation of whether your account was in scope for the December 2025 incident
- Request: malware scan on shared hosting environment
- Escalate if front-line support is unresponsive — this is a platform-level breach, not a user error

---

## Lessons Learned and Architectural Gaps

### Gap 1: No Account-Level Monitoring
Citadel Archer monitors what happens inside servers (file changes, process activity, auth logs) but has no visibility into the hosting control panel layer above them. The attacker operated at the hPanel level — adding SSH keys, changing database passwords, accessing the browser terminal — and none of this generated a Citadel alert.

**Planned remediation**: Hostinger API audit polling — periodically pull SSH keys, active sessions, API token list, and database credential state via the Hostinger MCP integration. Alert on any change we did not initiate. Target: v0.4.3.

### Gap 2: API Token Stored Plaintext
The Hostinger API token in `data/user_preferences.db` is stored in plaintext. If a VPS is compromised and the `data/` directory is accessible (e.g., if Citadel Archer is running on that VPS), the token is stolen immediately.

**Planned remediation**: Encrypt the Hostinger API token using the same vault encryption used for SSH credentials. Never store it plaintext.

### Gap 3: No Agent Integrity Verification
We have no way to verify that a reporting agent has not been tampered with. A compromised VPS running `citadel-daemon` could send false or misleading threat reports.

**Planned remediation**: Agent report signing — daemon signs reports with a private key provisioned at enrollment; dashboard verifies signature before trusting report content.

### Gap 4: Vault Secrets on Compromised Hosts
`machine.key` on a compromised VPS means vault-encrypted credentials are decryptable by the attacker.

**Planned remediation**: Machine keys should never be stored on the VPS itself. The VPS daemon should only hold a bearer token for the ext-agent API; all secrets (SSH keys, API tokens) stay on the home machine's vault.

---

## Context: Hostinger December 2025 Breach

Based on research (Perplexity report, 2026-03-06), Hostinger disclosed a shared hosting breach in December 2025. The breach may have given attackers access to account credentials, session tokens, or internal platform systems. This is consistent with the account-level access pattern observed — the attacker does not appear to be guessing passwords or exploiting individual app vulnerabilities, but operating with legitimate platform-level credentials.

This is the second known major Hostinger breach (the first was August 2019, affecting 14 million accounts). The pattern of hosting provider platform-level breaches is an industry-wide problem and underscores why Citadel Archer's mission — defense-in-depth monitoring at every layer — is critical.

---

## Related References
- MITRE ATT&CK T1098.004: Account Manipulation: SSH Authorized Keys
- MITRE ATT&CK T1546.004: Event Triggered Execution: Unix Shell Configuration Modification
- MITRE ATT&CK T1505.003: Server Software Component: Web Shell
- Bracketed Paste Mode: https://cirw.in/blog/bracketed-paste
- ANSI Terminal Abuse: https://www.cyberark.com/resources/threat-research-blog/dont-trust-this-title-abusing-terminal-emulators-with-ansi-escape-characters
- Hostinger VPS Hardening: https://www.hostinger.com/ca/tutorials/vps-security
