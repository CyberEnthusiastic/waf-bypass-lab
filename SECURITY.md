# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in any of the AI Security Projects,
please **do not** open a public GitHub issue. Instead, report it privately by:

1. **GitHub Security Advisory** (preferred): Open a private advisory at
   `https://github.com/CyberEnthusiastic/<repo-name>/security/advisories/new`
2. **Email**: Contact the maintainer via the email listed on the GitHub profile
   at https://github.com/CyberEnthusiastic

### What to include

- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept if possible)
- Affected versions / commits
- Potential impact
- Any suggested mitigation

### Response timeline

| Stage | Target |
|-------|--------|
| Initial acknowledgment | 48 hours |
| Triage + severity assessment | 5 business days |
| Fix + disclosure coordination | 30 days for High/Critical, 90 days for Medium/Low |

## Supported Versions

Only the `main` branch receives security updates. Pin to a specific commit
if you need reproducible builds, but understand you will not receive fixes
unless you update.

## Security Best Practices

These tools are **defensive** security tools. However, several of them
(WAF Bypass Lab, AI SAST Scanner) can be misused if turned against systems
you do not own.

**Authorized use only.** Do not scan, test, or probe any system without
explicit written authorization from the system owner. The authors disclaim
all liability for misuse.

## Responsible Disclosure Hall of Fame

Reporters who follow responsible disclosure will be credited in the repo's
CHANGELOG unless they request anonymity.
