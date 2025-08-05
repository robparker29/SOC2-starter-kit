# Expert Detail Questions - AWS Inactive Users Script

Now that I understand the codebase architecture, here are the technical detail questions:

## Q6: Should the script extend the existing `SystemDataCollector` class at `soc2_automation/lib/soc2_collectors.py:18` with a new inactive user analysis method?
**Default if unknown:** Yes (maintains architectural consistency and reuses existing AWS user collection logic)

## Q7: What inactivity threshold should trigger findings - 90 days like the existing User Access Review script at `scripts/User Access Reviews/user_access_review.py:152`?
**Default if unknown:** Yes (consistent with existing script and common SOC 2 practice)

## Q8: Should the script create separate severity levels for console login inactivity vs access key inactivity, since access keys may be used for automation?
**Default if unknown:** Yes (console=HIGH after 90 days, access keys=MEDIUM after 180 days due to automation use)

## Q9: For multi-account support, should the script use cross-account IAM roles following AWS security best practices rather than storing multiple access keys?
**Default if unknown:** Yes (cross-account roles are more secure and align with SOC 2 security principles)

## Q10: Should findings be written using the existing `AccessReviewFinding` model at `soc2_automation/lib/soc2_models.py:80` for consistency with other SOC 2 automation?
**Default if unknown:** Yes (ensures consistent data structure and reporting formats across all SOC 2 tools)

---

**Next Step:** I'll ask these questions one at a time, starting with Q6.