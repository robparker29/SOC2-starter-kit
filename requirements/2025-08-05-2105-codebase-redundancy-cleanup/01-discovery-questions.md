# Discovery Questions - Codebase Redundancy Cleanup

Based on analysis of the SOC 2 starter kit codebase, I've identified several redundancies that complicate the beginner experience:

## Q1: Should we consolidate the duplicate UserAccessRecord models and AWS user collection logic between `scripts/User Access Reviews/user_access_review.py` and `soc2_automation/lib/soc2_models.py`?
**Default if unknown:** Yes (eliminates confusion about which version to use and maintains single source of truth)

## Q2: Should we move all scripts from the legacy `scripts/` directory structure into the unified `soc2_automation/` framework to reduce structural complexity?
**Default if unknown:** Yes (creates single entry point for beginners instead of multiple competing approaches)

## Q3: Should we consolidate the duplicate EvidenceItem models between `scripts/Evidence Collection/evidence_collection.py` and `soc2_automation/lib/soc2_models.py`?
**Default if unknown:** Yes (prevents beginners from having to understand multiple data model versions)

## Q4: Should we remove the `claude-code-requirements-builder/` directory since it's development tooling not needed for SOC 2 audit execution?
**Default if unknown:** Yes (removes non-essential complexity from the main audit workflow)

## Q5: Should we create a single unified CLI entry point that replaces the multiple scattered script entry points across different directories?
**Default if unknown:** Yes (provides clear, single command interface for beginners to execute all SOC 2 tasks)

---

**Next Step:** I'll ask these questions one at a time, starting with Q1.