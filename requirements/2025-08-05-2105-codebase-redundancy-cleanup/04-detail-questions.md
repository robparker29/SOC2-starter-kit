# Expert Detail Questions - Codebase Redundancy Cleanup

Based on my analysis of the redundant code and structural issues, here are the technical detail questions:

## Q6: Should we create a single unified evidence collector that replaces both `scripts/Evidence Collection/evidence_collection.py` (1,215 lines) and integrates with the existing framework at `soc2_automation/lib/soc2_collectors.py`?
**Default if unknown:** Yes (eliminates 1,000+ lines of duplicate collection logic and provides single comprehensive evidence gathering tool)

## Q7: Should we enhance `soc2_automation/inactive_users_detector.py` to absorb the functionality from `scripts/User Access Reviews/user_access_review.py` since they overlap in user access analysis?
**Default if unknown:** Yes (creates single comprehensive user access review tool instead of two competing approaches)

## Q8: Should we create a main CLI entry point at `soc2_automation/soc2_cli.py` that provides subcommands like `soc2-audit user-access-review` and `soc2-audit evidence-collection` to replace multiple script entry points?
**Default if unknown:** Yes (provides single command interface that beginners can learn instead of navigating multiple scripts)

## Q9: Should we standardize all scripts to use the configuration validation pattern from `soc2_utils.py:validate_config_completeness()` to eliminate inconsistent config handling across scripts?
**Default if unknown:** Yes (prevents beginners from encountering different error messages and config requirements per script)

## Q10: Should we move all functionality out of the `scripts/` directory and deprecate it entirely to eliminate the dual-directory confusion for beginners?
**Default if unknown:** Yes (creates single `soc2_automation/` directory as the clear entry point for all SOC 2 audit functionality)

---

**Next Step:** I'll ask these questions one at a time, starting with Q6.