# Expert Detail Answers - Codebase Redundancy Cleanup

## Q6: Should we create a single unified evidence collector that replaces both `scripts/Evidence Collection/evidence_collection.py` (1,215 lines) and integrates with the existing framework at `soc2_automation/lib/soc2_collectors.py`?
**Answer:** Yes

## Q7: Should we enhance `soc2_automation/inactive_users_detector.py` to absorb the functionality from `scripts/User Access Reviews/user_access_review.py` since they overlap in user access analysis?
**Answer:** Yes

## Q8: Should we create a main CLI entry point at `soc2_automation/soc2_cli.py` that provides subcommands like `soc2-audit user-access-review` and `soc2-audit evidence-collection` to replace multiple script entry points?
**Answer:** Yes

## Q9: Should we standardize all scripts to use the configuration validation pattern from `soc2_utils.py:validate_config_completeness()` to eliminate inconsistent config handling across scripts?
**Answer:** Yes

## Q10: Should we move all functionality out of the `scripts/` directory and deprecate it entirely to eliminate the dual-directory confusion for beginners?
**Answer:** Yes

---

**Detail Phase Complete. Starting Phase 5: Requirements Documentation**