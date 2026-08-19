# Security Policy

## Official repository mirrors

CipherShelf is maintained primarily on Gitee (the platform where the fnOS `manifest` resolves `maintainer_url`) and mirrored to GitHub. When filing a vulnerability report, prefer the host whose private security-advisory channel you have access to.

- Primary: https://gitee.com/akun15623/ciphershelf
- Mirror: https://github.com/akun15623/CipherShelf

Both remotes track the same commits; issues and advisories are not guaranteed to be cross-posted. Use the GitHub mirror if you want GitHub's private advisory workflow.

## Supported versions

Only the latest release receives security fixes. Index formats v1 and v2 are supported for decryption and migration only; new indexes are written as format v3. Encrypted files continue to use the authenticated v2 file format.

## Reporting a vulnerability

Do not publish an exploit, password, index file, plaintext filename, or affected user's data in a public issue.

Use the hosting platform's private security-advisory channel where available. If the repository host has no private channel, contact the maintainer through the profile listed in the package manifest and request a private contact method before sharing details.

Include the affected version, deployment type, reproduction steps using synthetic data, expected impact, and any suggested mitigation. The maintainer should acknowledge a report within seven days and coordinate disclosure after a fix or mitigation is available.

## Security boundaries

- Anyone who knows the vault password can view names and request encryption/decryption of authorized paths.
- CipherShelf does not protect against a compromised host, a process with permission to inspect its memory, or an administrator who can read the preset password environment variable.
- Availability and recovery require independent backups. Encryption is not a backup mechanism.
- HTTPS is required when traffic crosses an untrusted network.
