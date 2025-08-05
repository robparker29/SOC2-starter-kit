# Discovery Questions - AWS Inactive Users Script

Based on analysis of the existing SOC 2 automation codebase, here are the key discovery questions:

## Q1: Should this script integrate with your existing SOC 2 automation framework in the `soc2_automation` directory?
**Default if unknown:** Yes (leverages existing SOC2Utils, logging, and UserAccessRecord models for consistency)

## Q2: Do you want the script to generate audit-ready reports in CSV format like the existing User Access Review script?
**Default if unknown:** Yes (maintains consistency with existing compliance reporting format)

## Q3: Should the script check for inactive access keys in addition to inactive console logins?
**Default if unknown:** Yes (access keys represent programmatic access and are security-critical for SOC 2)

## Q4: Do you want the script to automatically create remediation tickets or notifications for inactive users found?
**Default if unknown:** No (safer to review findings manually before taking action on user accounts)

## Q5: Should the script analyze IAM users across multiple AWS accounts if configured?
**Default if unknown:** No (start with single account analysis to avoid complexity and cross-account permissions)

---

**Next Step:** I'll ask these questions one at a time, starting with Q1.