# Discovery Questions - Evidence Collection Scripts Priority

## Q1: Should the new evidence collection scripts integrate with the existing CLI interface at soc2_cli.py?
**Default if unknown:** Yes (maintains consistency with existing user experience and leverages the established command structure)

## Q2: Will the database security evidence collector need to connect directly to production databases?
**Default if unknown:** No (better to collect evidence through configuration files and logs to minimize security risk)

## Q3: Should the master orchestration script generate reports in the same formats as existing tools (CSV/JSON)?
**Default if unknown:** Yes (consistency with current evidence_collector.py output formats)

## Q4: Will the network security configuration collector need real-time monitoring capabilities?
**Default if unknown:** No (evidence collection is typically point-in-time snapshots for audit purposes)

## Q5: Should the vendor & third-party access audit script integrate with existing ticketing systems for remediation?
**Default if unknown:** Yes (follows the pattern established in inactive_users_detector.py for ticket creation)

## Question Generation Context:
- Existing framework has evidence_collector.py with multi-cloud support
- CLI interface (soc2_cli.py) already supports evidence-collection command
- Current system uses standardized data models (soc2_models.py)
- Framework includes ticket creation capabilities
- Output formats are already standardized (CSV/JSON)
- Security-focused architecture with proper error handling