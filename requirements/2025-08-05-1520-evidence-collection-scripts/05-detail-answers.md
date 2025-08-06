# Detail Answers - Evidence Collection Scripts Priority

## Q1: Should the new database security collector extend MultiCloudDataCollector to support cloud databases (RDS, Azure SQL, Cloud SQL)?
**Answer:** Yes
**Rationale:** Maintains consistency with existing multi-cloud architecture and supports comprehensive database evidence collection across cloud and on-premise systems.

## Q2: Should the master orchestration script use the existing parallel execution pattern from multicloud_collectors.py with ThreadPoolExecutor?
**Answer:** Yes
**Rationale:** Leverages proven parallel execution framework with existing max_concurrent_clouds configuration for efficient evidence collection coordination.

## Q3: Should the network security collector create new data models following the CloudNetworkRule pattern in cloud_providers.py?
**Answer:** Yes
**Rationale:** Maintains data model consistency and leverages existing network rule abstractions for cross-cloud compatibility (AWS Security Groups, Azure NSGs, GCP Firewall Rules).

## Q4: Should the vendor access auditor integrate with the existing JIRA configuration in soc2_unified_config.json for ticket creation?
**Answer:** Yes
**Rationale:** Follows established pattern from inactive_users_detector.py and reuses existing ticket creation infrastructure for automated remediation workflows.

## Q5: Should the evidence collection scripts add new evidence types to the existing ['ACCESS', 'CONFIG', 'MONITORING', 'CHANGE_MANAGEMENT'] list in the CLI?
**Answer:** Yes
**Rationale:** Extends current evidence-types argument to include DATABASE_SECURITY, NETWORK_SECURITY, VENDOR_ACCESS for granular evidence collection control.