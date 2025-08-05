# Requirements Specification: SOC 2 Codebase Redundancy Cleanup

## Problem Statement
The SOC 2 starter kit contains significant redundant code, duplicate functionality, and confusing structural complexity that makes it difficult for beginners to execute SOC 2 audits. The codebase has grown organically with multiple competing approaches, duplicate data models, and scattered entry points that create confusion rather than clarity.

## Solution Overview
Consolidate the codebase into a clean, unified structure centered on the `soc2_automation/` framework. Eliminate redundant code, standardize data models and utilities, create a single CLI entry point, and provide clear beginner-friendly workflows.

## Current State Analysis
- **~2,800 lines** of redundant code across scattered scripts
- **5+ different entry points** for similar functionality
- **3 duplicate UserAccessRecord implementations**
- **4 duplicate AWS user collection methods**
- **Dual directory structure** creating confusion (`scripts/` vs `soc2_automation/`)

## Target State
- **~1,500 lines** of clean, modular code
- **Single CLI entry point** with clear subcommands
- **Unified data models** and utilities
- **Single directory structure** (`soc2_automation/` only)
- **Clear beginner workflow** with consistent interfaces

## Functional Requirements

### F1: Code Consolidation
- **F1.1**: Remove duplicate UserAccessRecord implementations, standardize on `soc2_automation/lib/soc2_models.py`
- **F1.2**: Remove duplicate EvidenceItem implementations, use centralized model
- **F1.3**: Consolidate AWS/AD collection methods into single implementations in `soc2_collectors.py`
- **F1.4**: Remove duplicate utility functions (SSH, file hashing, config loading)

### F2: Script Migration and Enhancement
- **F2.1**: Create unified evidence collector replacing `scripts/Evidence Collection/evidence_collection.py`
- **F2.2**: Enhance `inactive_users_detector.py` to absorb functionality from `scripts/User Access Reviews/user_access_review.py`
- **F2.3**: Migrate all functionality from `scripts/` directory to `soc2_automation/`
- **F2.4**: Remove legacy `scripts/` directory entirely

### F3: Unified CLI Interface
- **F3.1**: Create main CLI entry point at `soc2_automation/soc2_cli.py`
- **F3.2**: Provide subcommands: `user-access-review`, `evidence-collection`, `config-drift-detection`, `inactive-users`
- **F3.3**: Consistent argument parsing and help documentation across all commands
- **F3.4**: Unified configuration format and validation

### F4: Configuration Standardization
- **F4.1**: Standardize all scripts to use `soc2_utils.py:validate_config_completeness()`
- **F4.2**: Create single configuration schema that works across all tools
- **F4.3**: Consistent error messages and troubleshooting guidance
- **F4.4**: Example configuration templates for common scenarios

### F5: Directory Structure Cleanup
- **F5.1**: Remove `claude-code-requirements-builder/` directory (development tooling)
- **F5.2**: Consolidate all audit functionality under `soc2_automation/`
- **F5.3**: Clear directory structure with logical organization
- **F5.4**: Updated documentation reflecting single entry point

## Technical Requirements

### T1: File Removals
- **Remove entirely**: `scripts/User Access Reviews/user_access_review.py` (293 lines)
- **Remove entirely**: `scripts/Evidence Collection/evidence_collection.py` (1,215 lines)
- **Remove entirely**: `scripts/Configuration Drift Detection/` directory (contains only README)
- **Remove entirely**: `claude-code-requirements-builder/` directory

### T2: Code Consolidation
- **Primary Framework**: Keep `soc2_automation/lib/` as single source of truth
  - `soc2_models.py` - Unified data models
  - `soc2_collectors.py` - Consolidated collection methods  
  - `soc2_utils.py` - Centralized utilities
- **Enhanced Scripts**: 
  - `inactive_users_detector.py` → Enhanced user access review tool
  - New: `evidence_collector.py` → Unified evidence collection
  - New: `soc2_cli.py` → Main CLI entry point

### T3: CLI Structure
```bash
# Single command interface
soc2-audit --help
soc2-audit user-access-review --config config.json
soc2-audit evidence-collection --config config.json --controls CC6.1,CC6.2
soc2-audit config-drift-detection --config config.json
soc2-audit inactive-users --config config.json --threshold 90
```

### T4: Configuration Schema
```json
{
  "aws": {
    "access_key": "...",
    "secret_key": "...",
    "region": "us-east-1",
    "accounts": [...]
  },
  "active_directory": {
    "server": "...",
    "user": "...",
    "password": "...",
    "search_base": "..."
  },
  "github": {
    "token": "...",
    "org_name": "..."
  },
  "jira": {
    "server": "...",
    "username": "...",
    "api_token": "...",
    "project_key": "..."
  },
  "soc2_settings": {
    "create_tickets": false,
    "output_directory": "reports/",
    "evidence_retention_days": 365
  }
}
```

## Implementation Plan

### Phase 1: Data Model Consolidation
1. **Update all imports** to use `soc2_automation/lib/soc2_models.py`
2. **Remove duplicate classes** from individual scripts
3. **Test compatibility** with existing functionality
4. **Validate data consistency** across all tools

### Phase 2: Collection Method Consolidation
1. **Enhance `soc2_collectors.py`** with comprehensive methods
2. **Remove duplicate collection code** from individual scripts
3. **Create specialized wrapper methods** for different use cases
4. **Add comprehensive error handling** and logging

### Phase 3: CLI Creation
1. **Create `soc2_cli.py`** with argparse subcommands
2. **Implement subcommand routing** to existing enhanced scripts
3. **Standardize configuration handling** across all commands
4. **Add comprehensive help and documentation**

### Phase 4: Script Migration
1. **Create new `evidence_collector.py`** using framework
2. **Enhance `inactive_users_detector.py`** with user access review features
3. **Update `config_drift_processor.py`** to use standardized utilities
4. **Remove legacy scripts** from `scripts/` directory

### Phase 5: Documentation and Cleanup
1. **Update README.md** with single workflow
2. **Create beginner quick-start guide**
3. **Remove development tooling directories**
4. **Update example configurations**

## Files to Create/Modify

### New Files:
- `soc2_automation/soc2_cli.py` - Main CLI entry point
- `soc2_automation/evidence_collector.py` - Unified evidence collection
- `soc2_automation/config/soc2_config_schema.json` - Configuration validation schema

### Modified Files:
- `soc2_automation/inactive_users_detector.py` - Enhanced with user access review features
- `soc2_automation/lib/soc2_collectors.py` - Add missing collection methods
- `soc2_automation/lib/soc2_utils.py` - Enhanced configuration validation
- `README.md` - Updated with single workflow approach

### Removed Files:
- `scripts/User Access Reviews/user_access_review.py`
- `scripts/Evidence Collection/evidence_collection.py`
- `scripts/Configuration Drift Detection/` (directory)
- `claude-code-requirements-builder/` (directory)

## Acceptance Criteria

### AC1: Code Reduction
- [ ] Codebase reduced from ~2,800 to ~1,500 lines
- [ ] No duplicate data models across scripts
- [ ] No duplicate collection methods across scripts
- [ ] Single implementation of utility functions

### AC2: Single Entry Point
- [ ] `soc2-audit` command provides all functionality
- [ ] Consistent subcommand interface across all tools
- [ ] Unified help documentation and argument parsing
- [ ] Single configuration format works with all commands

### AC3: Directory Structure
- [ ] All audit functionality under `soc2_automation/` only
- [ ] No competing directory structures
- [ ] Development tooling removed from main repository
- [ ] Clear logical organization of files

### AC4: Beginner Experience
- [ ] Single command to learn: `soc2-audit`
- [ ] Consistent error messages and troubleshooting
- [ ] Clear workflow documentation
- [ ] Example configurations that work across tools

### AC5: Functionality Preservation
- [ ] All existing functionality maintained
- [ ] No loss of features during consolidation
- [ ] Enhanced capabilities through integration
- [ ] Backward compatibility where needed

## Benefits for Beginners

### Before Cleanup:
- Must learn 5+ different script interfaces
- Navigate confusing dual directory structure
- Understand multiple data model versions
- Handle inconsistent configuration formats
- Deal with scattered documentation

### After Cleanup:
- Learn single `soc2-audit` command interface
- Work with unified `soc2_automation/` directory
- Use consistent data models and outputs
- Single configuration format for all tools
- Clear workflow documentation and examples

## Risk Mitigation

- **Functionality Loss**: Comprehensive testing during migration
- **Configuration Breakage**: Maintain backward compatibility where possible
- **User Disruption**: Clear migration guide and deprecation notices
- **Integration Issues**: Incremental rollout with validation at each phase

This cleanup will transform the SOC 2 starter kit from a confusing collection of scripts into a professional, beginner-friendly audit automation toolkit.