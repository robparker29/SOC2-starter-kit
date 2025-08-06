# Detail Questions - Evidence Collection Scripts Priority

## Q1: Should the new database security collector extend MultiCloudDataCollector to support cloud databases (RDS, Azure SQL, Cloud SQL)?
**Default if unknown:** Yes (maintains consistency with existing multi-cloud architecture in multicloud_collectors.py and supports comprehensive database evidence collection)

## Q2: Should the master orchestration script use the existing parallel execution pattern from multicloud_collectors.py with ThreadPoolExecutor?
**Default if unknown:** Yes (leverages proven parallel execution framework with max_concurrent_clouds configuration already in place)

## Q3: Should the network security collector create new data models following the CloudNetworkRule pattern in cloud_providers.py?
**Default if unknown:** Yes (maintains data model consistency and leverages existing network rule abstractions for cross-cloud compatibility)

## Q4: Should the vendor access auditor integrate with the existing JIRA configuration in soc2_unified_config.json for ticket creation?
**Default if unknown:** Yes (follows established pattern from inactive_users_detector.py and reuses existing ticket creation infrastructure)

## Q5: Should the evidence collection scripts add new evidence types to the existing ['ACCESS', 'CONFIG', 'MONITORING', 'CHANGE_MANAGEMENT'] list in the CLI?
**Default if unknown:** Yes (extends current evidence-types argument in soc2_cli.py to include DATABASE_SECURITY, NETWORK_SECURITY, VENDOR_ACCESS for granular evidence collection)