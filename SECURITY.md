# Security Policy

CredVault stores secrets in the Windows Credential Manager and injects them into
child processes. Bugs in that path can leak credentials, so reports are taken
seriously and handled privately until a fix is available.

## Supported versions

Only the latest release and the `main` branch receive security fixes.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Use GitHub's private vulnerability reporting for this repository:

https://github.com/heidrickla/CredVault/security/advisories/new

Include, where you can:

- A description of the issue and its impact (for example, which credential
  values could be exposed and to whom).
- Steps to reproduce, or a proof of concept.
- The version or commit you tested against.

You can expect an acknowledgement within 7 days. Once the issue is confirmed,
a fix will be prepared and released, and a security advisory published with
credit to the reporter unless you ask otherwise.

## Scope notes

CredVault relies on Windows DPAPI for encryption at rest, scoped to the current
Windows user. Attacks that require running code as that same user with access
to the Credential Manager are outside the threat model, since such code can
already read the credentials directly. Reports about CredVault exposing values
beyond the launched child process, logging secret values, or bypassing its
launch-time verification are in scope.
