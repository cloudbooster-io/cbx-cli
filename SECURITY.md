# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in `cbx-cli`,
please report it privately. **Do not open a public GitHub issue.**

Preferred: open a private report through GitHub Security Advisories —
[**Report a vulnerability**](https://github.com/cloudbooster-io/cbx-cli/security/advisories/new).
This keeps the report, our discussion, and any fix coordinated in one place.

Alternatively, email **security@cloudbooster.io**.

Please include:

- A description of the issue and its potential impact
- Steps to reproduce (proof-of-concept, affected version, platform)
- Any suggested mitigation, if known

If possible, encrypt sensitive details. We will acknowledge receipt
within 5 business days.

## Disclosure policy

We follow a **coordinated disclosure** model with a 90-day window:

- Day 0: Report received and acknowledged.
- Day 0–90: We investigate, develop a fix, and prepare a release.
- By day 90: The issue is publicly disclosed, either via a release
  with the fix or — if a fix is not yet available — via a security
  advisory describing the issue and any available mitigations.

We may extend the window by mutual agreement when a fix requires
significant coordination across downstream consumers. We will not
extend it unilaterally.

## Supported versions

Security fixes are issued against the latest released minor version.
Older versions are supported on a best-effort basis only.

## Scope

In scope: the `cbx` binary built from this repository, including its
authentication, configuration, and network behavior.

Out of scope: third-party services that `cbx` integrates with (report
those to the respective vendor), and issues in dependencies that have
no exploitation path through `cbx-cli` itself.

## Known limitations

- **File keyring backend (`CBX_KEYRING_BACKEND=file`)** encrypts stored
  credentials with a fixed, source-published passphrase. On-disk tokens are
  therefore obfuscated rather than meaningfully protected. The files live in
  `CBX_KEYRING_FILE_DIR` if set, otherwise in a `cbx-keyring` directory
  created mode 0700 under the OS user cache dir (`os.UserCacheDir()`), with a
  fallback to the system temp dir only when the cache dir is unavailable. The
  private directory limits casual exposure on shared machines but does not
  change the obfuscation-only nature of the encryption. Use this backend only
  as a convenience fallback for throwaway or headless contexts; prefer a real
  OS keyring (macOS Keychain, Secret Service, Windows Credential Manager) for
  long-lived credentials. Hardening to a user-supplied passphrase is planned.
