# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities through GitHub's private vulnerability reporting:

<https://github.com/osrg/gobgp/security/advisories/new>

Do **not** open a public issue or report to third-party CVE numbering authorities (CNAs). CVEs for this project are managed by the maintainers through GitHub Security Advisories.

Please include a reproducer that runs against a released version, and state
the version you tested.

## Scope

We assign a CVE when input from an untrusted source alone breaks memory
safety or availability of `gobgpd`. Untrusted sources are the BGP session,
the RPKI-RTR connection, the ZAPI connection to zebra, and BFD packets.

Examples in scope:

- a panic or a fatal error
- a read or a write outside a buffer
- an unbounded allocation that leads to OOM
- a deadlock or a livelock that stops the daemon

Any other impact is out of scope, even when a peer can trigger it over the
wire. A wrong routing decision, a violation of an RFC, and a wrong message
sent to a peer are ordinary bugs.

## Not in scope

The following are ordinary bugs. Please open a GitHub issue or send a pull
request for them. We fix them, but we do not assign a CVE.

- Anything that requires access to the gRPC management API. A caller of that
  API can already add peers, add and delete routes, and stop the daemon. We
  treat every caller as trusted.
- Anything in the `gobgp` command. It is a client of that API. It also
  parses local files that the operator chooses, such as the MRT file given
  to `gobgp mrt inject`. Those files are trusted input.
- Anything that requires a non-default configuration that grants the
  attacker the ability in question.
- Protocol conformance bugs and wrong routing decisions. See Scope.

## Use of AI tools

You may use AI tools to find an issue and to write the report. Please tell
us if you did. The reporter is responsible for the content of the report,
not the tool. Check every claim before you send it.

## Supported Versions

Only the latest release is supported with security updates.
