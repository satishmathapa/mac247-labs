# NIST SP 800-53 Rev. 5 Control Mapping
## CM-8: System Component Inventory
- Requirement: Maintain an accurate and up-to-date inventory of system components.
- Evidence: assets.csv, patch_candidates.csv, and the inventory generated using export_inventory.py.
## CM-3: Configuration Change Control
- Requirement: Review, approve, document, and monitor changes to system configurations.
- Evidence: change_record.md, service.conf.bak, and the rollback test showing SHA-256 digest verification.
## SI-2: Flaw Remediation
- Requirement: Identify, report, and correct system security flaws.
- Evidence: patch_candidates.csv, package upgrades for curl, openssh-server, and python3, and dpkg-query version verification.
## RA-3: Risk Assessment
- Requirement: Assess security risks to system assets and update the assessment when conditions change.
- Evidence: score_before.txt, score_after.txt, and the risk register generated during session 7.
## AC-2: Account Management
- Requirement: Manage user accounts through approved creation, review, modification, and disabling procedures.
- Evidence: proofing.md, identities.csv, and the account provisioning and disabling commands completed during the lab.
## AC-2(3): Disable Accounts
- Requirement: Disable accounts that have been inactive for a defined period.
- Evidence: mac247_backup was locked, and its login shell was set to /usr/sbin/nologin. Account status was verified using passwd -S and identities_after.csv.
## AC-6: Least Privilege
- Requirement: Give users only the permissions needed to perform their assigned tasks.
- Evidence: entitlements_before.csv, entitlements_after.csv, and lab2_s08_entitlements_closed.png show the removal of mac247_backup from the mac247bkp group.
## IA-4: Identifier Management
- Requirement: Manage user identifiers and prevent inappropriate reuse.
- Evidence: identities_after.csv records user IDs (UIDs). The mac247_backup account was disabled rather than deleted, preserving its UID and file ownership for auditing .


