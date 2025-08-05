# Discovery Answers - Codebase Redundancy Cleanup

## Q1: Should we consolidate the duplicate UserAccessRecord models and AWS user collection logic between `scripts/User Access Reviews/user_access_review.py` and `soc2_automation/lib/soc2_models.py`?
**Answer:** Yes

## Q2: Should we move all scripts from the legacy `scripts/` directory structure into the unified `soc2_automation/` framework to reduce structural complexity?
**Answer:** Yes

## Q3: Should we consolidate the duplicate EvidenceItem models between `scripts/Evidence Collection/evidence_collection.py` and `soc2_automation/lib/soc2_models.py`?
**Answer:** Yes

## Q4: Should we remove the `claude-code-requirements-builder/` directory since it's development tooling not needed for SOC 2 audit execution?
**Answer:** Yes

## Q5: Should we create a single unified CLI entry point that replaces the multiple scattered script entry points across different directories?
**Answer:** Yes

---

**Discovery Phase Complete. Starting Phase 3: Context Gathering**