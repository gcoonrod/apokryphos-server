# Security Policy

We take the security of apokryphos-server seriously. This project is a **blind, zero-trust** server: it will handle cryptographic material and will operate on the explicit assumption that the server operator may be hostile or compromised. Vulnerabilities — especially in authentication, cryptographic handling, or anything that could expose user data — must be reported privately so that fixes can be coordinated before public disclosure.

## Reporting a vulnerability

**Please use GitHub's Private Security Advisories.** From this repository's GitHub page, click the **Security** tab, then **"Report a vulnerability"**. That flow gives you a private channel that only the project maintainers can see, and it lets us coordinate a fix and disclosure with you.

**Do not** file a public GitHub issue, post in discussions, or otherwise share the vulnerability publicly until a fix has been coordinated. Public disclosure before mitigation directly endangers users.

## What to include in your report

Please include as much of the following as you can:

- **Affected version or commit**: a tag, branch name, or commit SHA.
- **Steps to reproduce**: the most concise reproduction you have. A minimal proof-of-concept is ideal but not required.
- **Impact assessment**: what an attacker could do with this vulnerability. If you are uncertain, describe what you observed and we will help characterize the impact.
- **Suggested mitigation** (optional): if you have a fix or workaround in mind, share it.

If reproducing the vulnerability requires sensitive data, please describe what you used rather than sharing the data itself. We will work with you on a safe way to validate the report.

## Response timeline

- **Acknowledgement**: within **5 business days** of your report. If you have not heard from us by then, please feel free to bump the advisory thread.
- **Substantive response**: within **14 days**, including an initial assessment, our planned remediation timeline, and a coordinated disclosure date if appropriate.

We prefer **coordinated disclosure**: we will work with you to publish details only after a fix is available, and we will credit you in the advisory unless you ask us not to.

## Out of scope

The following are not considered in-scope security issues for this project, and reports about them may be closed without remediation:

- Denial-of-service attacks against the personal infrastructure of any individual maintainer.
- Social-engineering attacks targeting contributors, maintainers, or users.
- Theoretical attacks against configurations that the project does not support (e.g., running without the configured reverse proxy, disabling block-size enforcement).
- Vulnerabilities that require pre-existing administrator access to the operator's host machine.

If you are uncertain whether something is in scope, **err on the side of reporting it**. We would much rather receive an out-of-scope report than miss a real vulnerability.
