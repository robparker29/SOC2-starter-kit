# Context Findings - Evidence Collection Scripts Priority

## Existing Framework Analysis

### Core Architecture
- **Primary Framework**: Python-based SOC 2 automation with multi-cloud support
- **Main Entry Point**: `soc2_cli.py` - unified CLI interface with evidence-collection command
- **Base Classes**: 
  - `SystemDataCollector` (lib/soc2_collectors.py) - core data collection
  - `MultiCloudDataCollector` (lib/multicloud_collectors.py) - extends for multi-cloud
  - `EvidenceCollector` (evidence_collector.py) - current evidence collection implementation

### Integration Points Identified

#### 1. CLI Integration (soc2_cli.py)
- **Current Command**: `evidence-collection` already exists (lines 148-160)
- **Integration Pattern**: Add new subcommands or extend existing evidence-types
- **Existing Arguments**: `--controls`, `--evidence-types`, `--output-dir`
- **Current Evidence Types**: ACCESS, CONFIG, MONITORING, CHANGE_MANAGEMENT

#### 2. Data Models (lib/soc2_models.py)
- **Standard Models**: UserAccessRecord, SystemConfiguration, EvidenceItem
- **Multi-Cloud Models**: CloudIdentity, CloudNetworkRule, CloudAuditEvent
- **Pattern**: All use @dataclass decorator with serialize_dataclass function

#### 3. Configuration System
- **Config File**: soc2_unified_config.json with sections for each system
- **Evidence Section**: Lines 70-75 define evidence_collection settings
- **Pattern**: Each script gets its own config section

### SOC 2 Control Requirements (from research)

#### CC6.1 (Logical Access) Evidence Needs:
- Access control software and rule sets documentation
- User identification and validation procedures
- Network segmentation documentation
- Access point control records

#### CC6.2 (Access Credentials) Evidence Needs:
- Access credential creation approval processes
- Credential removal procedures
- Periodic access reviews

#### CC6.7 (Data Protection) Evidence Needs:
- Encryption configuration details
- Data loss prevention procedures
- Removable media protection protocols

#### CC7.1 (System Operations) Evidence Needs:
- Network security configurations
- Firewall rules and security groups
- Network segmentation evidence

#### CC8.1 (Change Management) Evidence Needs:
- Change logs and approval records
- Deployment pipeline configurations
- Rollback procedures

#### CC9.1/CC9.2 (Vendor Management) Evidence Needs:
- Third-party access agreements
- External integration documentation
- Service provider access logging

### Implementation Patterns

#### 1. Multi-Cloud Support Pattern
```python
# From multicloud_collectors.py
def collect_multi_cloud_identities(self, providers: List[str] = None):
    if self.parallel_execution:
        results = self._collect_identities_parallel(providers)
    else:
        results = self._collect_identities_sequential(providers)
```

#### 2. CLI Command Pattern
```python
# From soc2_cli.py - Evidence collection command structure
def _add_evidence_collection_parser(self, subparsers):
    parser = subparsers.add_parser('evidence-collection')
    parser.add_argument('--controls', nargs='*')
    parser.add_argument('--evidence-types', nargs='*')
    parser.set_defaults(func=self._run_evidence_collection)
```

#### 3. Configuration Pattern
```json
// From soc2_unified_config.json
"evidence_collection": {
    "retention_days": 365,
    "output_format": ["csv", "json"],
    "create_tickets": false,
    "evidence_types": ["ACCESS", "CONFIG", "MONITORING", "CHANGE_MANAGEMENT"]
}
```

### Key Files for Modification

1. **soc2_cli.py** (lines 148-160, 228-245) - Add new evidence collection subcommands
2. **lib/soc2_models.py** - Add new data models for database/network evidence
3. **config/soc2_unified_config.json** - Add database/network/vendor sections
4. **New files needed**:
   - `database_security_collector.py`
   - `network_security_collector.py` 
   - `vendor_access_auditor.py`
   - `master_evidence_orchestrator.py`

### Related Features
- **Current evidence_collector.py** - Template for new collectors
- **inactive_users_detector.py** - Ticket creation pattern
- **multicloud_collectors.py** - Parallel execution pattern
- **cloud_providers.py** - Multi-cloud abstraction layer

### Technical Constraints
- All new scripts must extend existing base classes
- Must use standardized data models and serialization
- Configuration must follow existing JSON schema pattern
- Output formats must match existing CSV/JSON pattern
- Must integrate with existing logging and error handling