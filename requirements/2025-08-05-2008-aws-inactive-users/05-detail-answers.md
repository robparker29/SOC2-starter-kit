# Expert Detail Answers - AWS Inactive Users Script

## Q6: Should the script extend the existing `SystemDataCollector` class at `soc2_automation/lib/soc2_collectors.py:18` with a new inactive user analysis method?
**Answer:** Yes

## Q7: What inactivity threshold should trigger findings - 90 days like the existing User Access Review script at `scripts/User Access Reviews/user_access_review.py:152`?
**Answer:** Yes

## Q8: Should the script create separate severity levels for console login inactivity vs access key inactivity, since access keys may be used for automation?
**Answer:** Yes

## Q9: For multi-account support, should the script use cross-account IAM roles following AWS security best practices rather than storing multiple access keys?
**Answer:** Yes

## Q10: Should findings be written using the existing `AccessReviewFinding` model at `soc2_automation/lib/soc2_models.py:80` for consistency with other SOC 2 automation?
**Answer:** Yes

---

**Detail Phase Complete. Starting Phase 5: Requirements Documentation**