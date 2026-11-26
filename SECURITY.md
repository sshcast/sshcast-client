# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `sshcast-client` or any Sshcast component, please **do not** open a public GitHub issue.

Report vulnerabilities privately via:
- GitHub Security Advisories on the repository: https://github.com/sshcast/sshcast-client/security/advisories/new
- Email: `security@sshcast.net`

Please include reproduction steps, affected versions, and impact assessment.

## Security Model Summary

- **Zero-trust coordinator routing:** Coordinators cannot sign SSH challenges or forge `SignRequest` messages. `sshcast-client` independently verifies the relay's `NodeGrant` signature (`UserCert` when operator-certified), `ProcessContext.hostname == NodeGrant.node_id`, and the relay's Ed25519 signature over every `SignRequest` before prompting the user or touching local SSH keys.
- **Explicit human & session policy authorization:** Private keys never leave your workstation; every signature requires interactive approval or an explicit scoped 15-minute session rule.

## Verifying Release Artifacts

Release artifacts include `SHA256SUMS.txt` and GitHub Artifact Build Provenance Attestations:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
gh attestation verify <artifact> --owner sshcast
```
