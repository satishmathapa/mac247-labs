# Audit Finding AF-01
- Condition: The sudo package has the highest remaining residual risk score of 10.00 in score_after.txt and has not been fully treated.
- Criteria: NIST SP 800-53 Rev. 5, SI-2 (Flaw Remediation), requires organizations to identify, report, and correct system flaws.
- Cause: The sudo package was not included in the three selected patch treatements, leaving its residual risk unresolved.
- Effect: If the sudo package contains an unpatched security flaw, an attacker with local access could potentially exploit it to gain elevated privileges.
- Recommendation: Review adn patch sudo if an applicable security update is available, then verify the installed version and recalculate residual risk. Owner: System Administrator. Target date: 2026-10-22.

