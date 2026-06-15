# Security Policy

SNCheck is a defensive security tool. Please do not submit live exploit details for active
subnet repositories in public issues before maintainers have had a chance to respond.

## Reporting a vulnerability in SNCheck itself

If you find a security issue in the SNCheck CLI (for example, a way to make a scan execute
untrusted repository code), report it privately to the maintainers rather than opening a
public issue. We will coordinate a fix and disclosure.

## Responsible disclosure for findings in subnet repositories

SNCheck is designed to surface risk signals in third-party repositories. When you discover a
severe issue in a subnet repo using SNCheck, please follow a coordinated process:

1. The researcher finds a severe issue in a subnet repo.
2. The researcher reports it privately to the subnet maintainers and the SNCheck maintainers.
3. Maintainers confirm and coordinate a fix.
4. A public SNCheck rule or report can be published after the fix, or after a reasonable
   disclosure window.

### Default disclosure windows

- **7 days** for critical active key-theft risk.
- **30 days** for high severity issues.
- **90 days** for medium and lower severity issues.

Adjust based on severity and exploitability.

## Wording

SNCheck reports risks, not accusations. Use neutral, evidence-first language such as
"high risk finding" or "potential wallet exposure" rather than "scam" or "malicious owner".
