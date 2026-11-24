# Security policy

## Report a vulnerability

Do not open a public issue for a security problem. Use one of these:

- GitHub: the "Report a vulnerability" button on the Security tab of <https://github.com/aivorynet/warden>.
- Email: security@aivory.net

Include the version (`aivory-warden --version`), your OS, and the steps to reproduce. We answer within 5 working days. We ask you to give us 90 days to fix the problem before you publish it. We credit you in the changelog if you want.

## Supported versions

We fix security problems in the latest release only. Warden uses calendar versions (`YYYY.MM.patch`).

## Scope

In scope: the vault crypto and format, the IPC authentication, the MCP server and proxy, the native host, the installers and the release pipeline.

Out of scope: problems that need malware or shell access as your own OS user, and the limits that [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) lists as "do not defend against".

## Verify a release

Check each download against `SHA256SUMS` on the release page. See [docs/INSTALL.md](docs/INSTALL.md).
