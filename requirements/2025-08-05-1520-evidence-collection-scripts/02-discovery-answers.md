# Discovery Answers - Evidence Collection Scripts Priority

## Q1: Should the new evidence collection scripts integrate with the existing CLI interface at soc2_cli.py?
**Answer:** Yes
**Rationale:** Maintains consistency with existing user experience and leverages the established command structure.

## Q2: Will the database security evidence collector need to connect directly to production databases?
**Answer:** No
**Rationale:** Better to collect evidence through configuration files and logs to minimize security risk.

## Q3: Should the master orchestration script generate reports in the same formats as existing tools (CSV/JSON)?
**Answer:** Yes
**Rationale:** Consistency with current evidence_collector.py output formats ensures compatibility with existing workflows.

## Q4: Will the network security configuration collector need real-time monitoring capabilities?
**Answer:** No
**Rationale:** Evidence collection is typically point-in-time snapshots for audit purposes.

## Q5: Should the vendor & third-party access audit script integrate with existing ticketing systems for remediation?
**Answer:** Yes
**Rationale:** Follows the pattern established in inactive_users_detector.py for ticket creation and enables automated remediation workflows.