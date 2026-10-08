# Change Record CR-20261008-01
- Change window: 2026-10-08, start/end time to be confirmed, EDT
- Requested by / Approver: Satishma Thapa / Pending instructor approval
- Systems affected: Kali Linux ARM virtual machine; service.conf (TLS configuration)
- Reason: Reduce the security risk of disabling TLS peer verification, which could allow untrusted connections.
- Security impact assessment: Disabling TLS peer verification could allow an attacker to intercept or alter connections. Restoring verification may affect connections using untrusted certificates.
- Pre-change checkpoint: Back up service.conf as service.conf.bak and record its SHA-256 digest before making changes.
- Success criteria: TLS peer verification is enabled (verify_peer = true), and the configuration passes the automated check.
- Rollback trigger: The automated check fails or TLS peer verification is disabled (verify_peer = false).
- Backout plan: Restore the original configuration using cp service.conf.bak service.conf.
- Verification after rollback: Compare the restored service.conf SHA-256 digest with the original digest to confirm they match.

