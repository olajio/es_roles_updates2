#!/usr/bin/env python3
"""
Elasticsearch Role Auto-Updater (Multi-Cluster Version)

Automatically updates roles across multiple Elasticsearch clusters:
1. Adds required patterns (partial-*, restored-*) to remote cluster roles
2. Adds required patterns (partial-*, restored-*, elastic-cloud-logs-*) to CCS cluster roles
3. Syncs index patterns from remote clusters to CCS cluster roles
4. Grants Kibana feature privileges (Discover, Dashboard, Visualize) in CCS for existing spaces

Supports any number of clusters defined in the configuration file.

Usage:
    # Add patterns to prod, qa, dev and sync to CCS with Kibana privileges
    python es_role_auto_update.py --config config.json --roles role1 role2 \
        --remote-clusters prod qa dev --ccs-cluster ccs

    # Skip Kibana privilege updates
    python es_role_auto_update.py --config config.json --role-file roles.txt \
        --remote-clusters prod qa dev --ccs-cluster ccs --skip-kibana-privileges
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Set, List, Optional, Tuple
import logging

from es_role_manager_utils import (
    ElasticsearchRoleManager,
    KibanaClient,
    setup_logging,
)

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default patterns to inject into remote cluster roles
DEFAULT_REMOTE_INJECT_PATTERNS = {"partial-*", "restored-*"}

# Default patterns to inject into CCS cluster roles
DEFAULT_CCS_INJECT_PATTERNS = {"partial-*", "restored-*", "elastic-cloud-logs-*"}

# Default Kibana privileges to grant in CCS cluster
DEFAULT_CCS_KIBANA_PRIVILEGES = {
    "feature_discover.all",
    "feature_dashboard.all",
    "feature_visualize.all"
}

# Default paths
DEFAULT_BACKUP_DIR = "./backups"
DEFAULT_LOG_DIR = "./logs"
DEFAULT_CONFIG_FILE = "./es_clusters_config.json"

# ============================================================================


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Update Elasticsearch roles across multiple clusters with required patterns and sync to CCS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available clusters in config
  python es_role_auto_update.py --config es_clusters_config.json --list-clusters

  # Dry run: update prod, qa, dev and sync to CCS (with Kibana privileges)
  python es_role_auto_update.py --config es_clusters_config.json \\
      --roles Role1 Role2 \\
      --remote-clusters prod qa dev \\
      --ccs-cluster ccs \\
      --dry-run

  # Update without Kibana privilege changes
  python es_role_auto_update.py --config es_clusters_config.json \\
      --roles Role1 \\
      --remote-clusters prod qa dev \\
      --ccs-cluster ccs \\
      --skip-kibana-privileges

  # Use roles from file
  python es_role_auto_update.py --config es_clusters_config.json \\
      --role-file roles.txt \\
      --remote-clusters prod qa dev \\
      --ccs-cluster ccs

Config file format (es_clusters_config.json):
  {
    "clusters": {
      "prod": {
        "url": "https://prod-elasticsearch:9200",
        "api_key": "YOUR_API_KEY",
        "verify_ssl": false
      },
      "qa": { ... },
      "dev": { ... },
      "ccs": { ... }
    },
    "defaults": {
      "remote_inject_patterns": ["partial-*", "restored-*"],
      "ccs_inject_patterns": ["partial-*", "restored-*", "elastic-cloud-logs-*"],
      "ccs_kibana_privileges": ["feature_discover.all", "feature_dashboard.all", "feature_visualize.all"],
      "remote_clusters": ["prod", "qa", "dev"],
      "ccs_cluster": "ccs"
    }
  }

Inject Patterns:
  - Remote clusters (prod, qa, dev): partial-*, restored-*
  - CCS cluster: partial-*, restored-*, elastic-cloud-logs-*

Kibana Privileges (CCS only):
  - feature_discover.all (CSV export from Discover)
  - feature_dashboard.all (reports from Dashboard)
  - feature_visualize.all (full Visualize access)
        """
    )
    
    parser.add_argument(
        '--config',
        type=Path,
        default=Path(DEFAULT_CONFIG_FILE),
        help=f'Path to cluster configuration file (default: {DEFAULT_CONFIG_FILE})'
    )
    
    parser.add_argument(
        '--list-clusters',
        action='store_true',
        help='List available clusters from config and exit'
    )
    
    # Role selection
    role_group = parser.add_mutually_exclusive_group()
    role_group.add_argument(
        '--roles',
        nargs='+',
        help='Space-separated list of specific role names to update'
    )
    role_group.add_argument(
        '--role-file',
        type=Path,
        help='File containing role names (one per line) to update'
    )
    role_group.add_argument(
        '--all-matching',
        action='store_true',
        help='Update all roles that exist in all specified clusters'
    )
    
    # Cluster selection
    parser.add_argument(
        '--remote-clusters',
        nargs='+',
        help='Remote clusters to update with required patterns (e.g., prod qa dev)'
    )
    
    parser.add_argument(
        '--ccs-cluster',
        help='CCS cluster to sync patterns to (e.g., ccs)'
    )
    
    parser.add_argument(
        '--skip-remote',
        action='store_true',
        help='Skip updating remote clusters (only update CCS)'
    )
    
    parser.add_argument(
        '--skip-ccs',
        action='store_true',
        help='Skip updating CCS cluster (only update remote clusters)'
    )
    
    # Pattern options
    parser.add_argument(
        '--remote-inject-patterns',
        nargs='+',
        help='Patterns to inject into remote clusters (default: partial-*, restored-*)'
    )
    
    parser.add_argument(
        '--ccs-inject-patterns',
        nargs='+',
        help='Patterns to inject into CCS cluster (default: partial-*, restored-*, elastic-cloud-logs-*)'
    )
    
    parser.add_argument(
        '--skip-inject',
        action='store_true',
        help='Skip injecting required patterns'
    )
    
    # Kibana privilege options
    parser.add_argument(
        '--ccs-kibana-privileges',
        nargs='+',
        help='Kibana privileges to grant in CCS (default: feature_discover.all, feature_dashboard.all, feature_visualize.all)'
    )
    
    parser.add_argument(
        '--skip-kibana-privileges',
        action='store_true',
        help='Skip granting Kibana privileges in CCS cluster'
    )
    
    # Operational options
    parser.add_argument(
        '--backup-dir',
        type=Path,
        default=Path(DEFAULT_BACKUP_DIR),
        help=f'Directory to store role backups (default: {DEFAULT_BACKUP_DIR})'
    )
    
    parser.add_argument(
        '--log-dir',
        type=Path,
        default=Path(DEFAULT_LOG_DIR),
        help=f'Directory to store log files (default: {DEFAULT_LOG_DIR})'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be changed without making actual changes'
    )
    
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Skip backup creation (not recommended)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--report-only',
        action='store_true',
        help='Only generate a report without making any changes'
    )
    
    parser.add_argument(
        '--continue-on-error',
        action='store_true',
        help='Continue updating other roles if one fails'
    )
    
    return parser.parse_args()


def load_config(config_path: Path) -> Dict:
    """
    Load cluster configuration from JSON file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    logger = logging.getLogger(__name__)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Support both old format (prod/ccs at root) and new format (clusters dict)
    if 'clusters' not in config:
        # Convert old format to new format
        logger.info("Converting old config format to new format...")
        new_config = {
            'clusters': {},
            'defaults': {
                'remote_inject_patterns': list(DEFAULT_REMOTE_INJECT_PATTERNS),
                'ccs_inject_patterns': list(DEFAULT_CCS_INJECT_PATTERNS),
                'ccs_kibana_privileges': list(DEFAULT_CCS_KIBANA_PRIVILEGES),
                'remote_clusters': [],
                'ccs_cluster': None
            }
        }
        for key, value in config.items():
            if isinstance(value, dict) and 'url' in value:
                new_config['clusters'][key] = value
                if key == 'ccs':
                    new_config['defaults']['ccs_cluster'] = key
                else:
                    new_config['defaults']['remote_clusters'].append(key)
        config = new_config
    
    # Handle legacy source_clusters naming
    if 'defaults' in config:
        if 'source_clusters' in config['defaults'] and 'remote_clusters' not in config['defaults']:
            config['defaults']['remote_clusters'] = config['defaults']['source_clusters']
            logger.info("Converted 'source_clusters' to 'remote_clusters' in config")
        if 'inject_patterns' in config['defaults']:
            # Old single inject_patterns - use for both remote and CCS
            if 'remote_inject_patterns' not in config['defaults']:
                config['defaults']['remote_inject_patterns'] = config['defaults']['inject_patterns']
            if 'ccs_inject_patterns' not in config['defaults']:
                config['defaults']['ccs_inject_patterns'] = config['defaults']['inject_patterns'] + ['elastic-cloud-logs-*']
        # Set default Kibana privileges if not present
        if 'ccs_kibana_privileges' not in config['defaults']:
            config['defaults']['ccs_kibana_privileges'] = list(DEFAULT_CCS_KIBANA_PRIVILEGES)
    
    # Validate clusters exist
    if not config.get('clusters'):
        raise ValueError("No clusters defined in configuration file")
    
    # Validate each cluster has required fields
    required_fields = ['url', 'api_key']
    for cluster_name, cluster_config in config['clusters'].items():
        for field in required_fields:
            if field not in cluster_config:
                raise ValueError(f"Missing '{field}' in cluster '{cluster_name}' configuration")
    
    logger.info(f"Loaded configuration from: {config_path}")
    logger.info(f"Available clusters: {', '.join(config['clusters'].keys())}")
    
    return config


def list_clusters(config: Dict):
    """Print available clusters and exit"""
    print("\nAvailable clusters in configuration:")
    print("-" * 60)
    
    for name, cluster in config['clusters'].items():
        description = cluster.get('description', 'No description')
        url = cluster['url']
        print(f"  {name:15} - {url}")
        print(f"  {' '*15}   {description}")
        print()
    
    if 'defaults' in config:
        print("Default settings:")
        defaults = config['defaults']
        if defaults.get('remote_clusters'):
            print(f"  Remote clusters: {', '.join(defaults['remote_clusters'])}")
        if defaults.get('ccs_cluster'):
            print(f"  CCS cluster: {defaults['ccs_cluster']}")
        if defaults.get('remote_inject_patterns'):
            print(f"  Remote inject patterns: {', '.join(defaults['remote_inject_patterns'])}")
        if defaults.get('ccs_inject_patterns'):
            print(f"  CCS inject patterns: {', '.join(defaults['ccs_inject_patterns'])}")
        if defaults.get('ccs_kibana_privileges'):
            print(f"  CCS Kibana privileges: {', '.join(defaults['ccs_kibana_privileges'])}")


def load_roles_from_file(file_path: Path) -> List[str]:
    """
    Load role names from a file
    
    Args:
        file_path: Path to file containing role names
        
    Returns:
        List of role names
    """
    logger = logging.getLogger(__name__)
    
    if not file_path.exists():
        raise FileNotFoundError(f"Role file not found: {file_path}")
    
    roles = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                roles.append(line)
    
    logger.info(f"Loaded {len(roles)} role names from {file_path}")
    return roles


def get_patterns_from_role(role_def: Dict) -> Set[str]:
    """
    Extract all local index patterns from a role definition
    
    Args:
        role_def: Role definition dictionary
        
    Returns:
        Set of index patterns (excluding remote patterns with ':')
    """
    patterns = set()
    
    for index_entry in role_def.get('indices', []):
        for name in index_entry.get('names', []):
            # Only include local patterns (no cluster prefix)
            if ':' not in name:
                patterns.add(name.strip())
    
    return patterns


def analyze_role_for_injection(
    role_name: str,
    role_def: Dict,
    inject_patterns: Set[str],
    manager: ElasticsearchRoleManager
) -> Tuple[bool, Set[str]]:
    """
    Analyze a single role to determine what patterns need to be injected
    
    Args:
        role_name: Name of the role
        role_def: Role definition
        inject_patterns: Set of patterns to inject if missing
        manager: ElasticsearchRoleManager instance
        
    Returns:
        Tuple of (needs_update, patterns_to_add)
    """
    logger = logging.getLogger(__name__)
    
    # Skip reserved roles
    if role_def.get('metadata', {}).get('_reserved'):
        logger.debug(f"Skipping reserved role: {role_name}")
        return False, set()
    
    # Get existing patterns (normalized for comparison)
    existing_patterns = manager.get_existing_local_patterns(role_def)
    existing_normalized = {
        manager.normalize_pattern_for_comparison(p) for p in existing_patterns
    }
    
    patterns_to_add = set()
    
    # Check each inject pattern
    for pattern in inject_patterns:
        normalized = manager.normalize_pattern_for_comparison(pattern)
        if normalized not in existing_normalized:
            patterns_to_add.add(pattern)
    
    return bool(patterns_to_add), patterns_to_add


def analyze_ccs_role_for_sync(
    role_name: str,
    ccs_role_def: Dict,
    remote_roles: Dict[str, Dict],  # cluster_name -> role_def
    ccs_inject_patterns: Set[str],
    manager: ElasticsearchRoleManager,
    skip_inject: bool = False
) -> Dict:
    """
    Analyze a CCS role to determine all patterns that need to be added
    
    Args:
        role_name: Name of the role
        ccs_role_def: CCS role definition
        remote_roles: Dict mapping cluster name to role definition
        ccs_inject_patterns: Set of patterns to inject into CCS if missing
        manager: ElasticsearchRoleManager instance
        skip_inject: If True, skip injecting patterns
        
    Returns:
        Dictionary with patterns_to_add and sources breakdown
    """
    logger = logging.getLogger(__name__)
    
    # Skip reserved roles
    if ccs_role_def.get('metadata', {}).get('_reserved'):
        logger.debug(f"Skipping reserved role: {role_name}")
        return {'patterns_to_add': set(), 'sources': {'inject': set(), 'sync': {}}}
    
    # Get existing CCS patterns (normalized for comparison)
    existing_patterns = manager.get_existing_local_patterns(ccs_role_def)
    existing_normalized = {
        manager.normalize_pattern_for_comparison(p) for p in existing_patterns
    }
    
    patterns_to_add = set()
    sources = {'inject': set(), 'sync': {}}  # sync is dict: cluster_name -> patterns
    
    # 1. Check CCS inject patterns (if not skipped)
    if not skip_inject:
        for pattern in ccs_inject_patterns:
            normalized = manager.normalize_pattern_for_comparison(pattern)
            if normalized not in existing_normalized:
                patterns_to_add.add(pattern)
                sources['inject'].add(pattern)
                existing_normalized.add(normalized)  # Track as added
    
    # 2. Sync patterns from each remote cluster
    for cluster_name, role_def in remote_roles.items():
        if role_def is None:
            continue
        
        remote_patterns = get_patterns_from_role(role_def)
        cluster_sync = set()
        
        for pattern in remote_patterns:
            normalized = manager.normalize_pattern_for_comparison(pattern)
            if normalized not in existing_normalized:
                patterns_to_add.add(pattern)
                cluster_sync.add(pattern)
                existing_normalized.add(normalized)  # Track as added
        
        if cluster_sync:
            sources['sync'][cluster_name] = cluster_sync
    
    return {
        'patterns_to_add': patterns_to_add,
        'sources': sources
    }


def analyze_ccs_role_for_kibana(
    role_name: str,
    ccs_role_def: Dict,
    required_privileges: Set[str]
) -> Dict:
    """
    Analyze a CCS role for Kibana privilege updates
    
    Args:
        role_name: Name of the role
        ccs_role_def: CCS role definition
        required_privileges: Set of privileges to ensure exist
        
    Returns:
        Dictionary with needs_update, spaces, and missing_privileges
    """
    logger = logging.getLogger(__name__)
    
    # Skip reserved roles
    if ccs_role_def.get('metadata', {}).get('_reserved'):
        logger.debug(f"Skipping reserved role for Kibana: {role_name}")
        return {'needs_update': False, 'spaces': set(), 'missing_privileges': set()}
    
    needs_update, spaces, missing_privileges = ElasticsearchRoleManager.analyze_kibana_privileges(
        ccs_role_def, required_privileges
    )
    
    return {
        'needs_update': needs_update,
        'spaces': spaces,
        'missing_privileges': missing_privileges
    }


def update_single_role(
    manager: ElasticsearchRoleManager,
    role_name: str,
    role_def: Dict,
    patterns_to_add: Set[str],
    cluster_name: str,
    dry_run: bool = False
) -> bool:
    """
    Update a single role with new patterns
    
    Args:
        manager: ElasticsearchRoleManager instance
        role_name: Name of the role
        role_def: Current role definition
        patterns_to_add: Set of patterns to add
        cluster_name: Name of the cluster (for logging)
        dry_run: If True, don't actually update
        
    Returns:
        True if successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"  [{cluster_name}] [DRY RUN] Would add {len(patterns_to_add)} patterns")
        return True
    
    try:
        updated_role = manager.add_local_patterns_to_role(role_def, patterns_to_add)
        success = manager.update_role(role_name, updated_role)
        
        if success:
            logger.info(f"  [{cluster_name}] ✓ Successfully updated {role_name}")
        else:
            logger.error(f"  [{cluster_name}] ✗ Failed to update {role_name}")
        
        return success
    except Exception as e:
        logger.error(f"  [{cluster_name}] ✗ Error updating {role_name}: {e}")
        return False


def update_ccs_role_with_kibana(
    manager: ElasticsearchRoleManager,
    role_name: str,
    role_def: Dict,
    patterns_to_add: Set[str],
    kibana_update: Dict,
    kibana_privileges: Set[str],
    cluster_name: str,
    dry_run: bool = False,
    kibana_client: KibanaClient = None
) -> bool:
    """
    Update a CCS role with patterns and Kibana privileges
    
    Args:
        manager: ElasticsearchRoleManager instance
        role_name: Name of the role
        role_def: Current role definition
        patterns_to_add: Set of patterns to add
        kibana_update: Kibana analysis result
        kibana_privileges: Set of Kibana privileges to add
        cluster_name: Name of the cluster (for logging)
        dry_run: If True, don't actually update
        kibana_client: Optional KibanaClient for checking disabled features in spaces
        
    Returns:
        True if successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    if dry_run:
        changes = []
        if patterns_to_add:
            changes.append(f"{len(patterns_to_add)} patterns")
        if kibana_update.get('needs_update'):
            changes.append(f"Kibana privileges for {len(kibana_update['spaces'])} spaces")
        logger.info(f"  [{cluster_name}] [DRY RUN] Would add {', '.join(changes)}")
        return True
    
    try:
        updated_role = role_def
        
        # Add patterns if needed
        if patterns_to_add:
            updated_role = manager.add_local_patterns_to_role(updated_role, patterns_to_add)
        
        # Add Kibana privileges if needed
        if kibana_update.get('needs_update') and kibana_update.get('spaces'):
            updated_role = manager.add_kibana_privileges_to_role(
                updated_role,
                kibana_privileges,
                kibana_update['spaces'],
                kibana_client  # Pass the Kibana client for disabled features check
            )
        
        success = manager.update_role(role_name, updated_role)
        
        if success:
            logger.info(f"  [{cluster_name}] ✓ Successfully updated {role_name}")
        else:
            logger.error(f"  [{cluster_name}] ✗ Failed to update {role_name}")
        
        return success
    except Exception as e:
        logger.error(f"  [{cluster_name}] ✗ Error updating {role_name}: {e}")
        return False


def generate_report(
    remote_updates: Dict[str, Dict[str, Dict]],  # cluster -> role -> info
    ccs_updates: Dict[str, Dict],
    ccs_kibana_updates: Dict[str, Dict],
    output_file: Path,
    remote_inject_patterns: Set[str],
    ccs_inject_patterns: Set[str],
    ccs_kibana_privileges: Set[str],
    remote_clusters: List[str],
    ccs_cluster: str
):
    """Generate a detailed JSON report"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'config': {
            'remote_inject_patterns': sorted(list(remote_inject_patterns)),
            'ccs_inject_patterns': sorted(list(ccs_inject_patterns)),
            'ccs_kibana_privileges': sorted(list(ccs_kibana_privileges)),
            'remote_clusters': remote_clusters,
            'ccs_cluster': ccs_cluster
        },
        'summary': {
            'remote_clusters_updated': {
                cluster: len(updates) for cluster, updates in remote_updates.items()
            },
            'ccs_roles_to_update': len(ccs_updates),
            'ccs_kibana_updates': len([k for k, v in ccs_kibana_updates.items() if v.get('needs_update')])
        },
        'remote_updates': {},
        'ccs_updates': {},
        'ccs_kibana_updates': {}
    }
    
    # Remote cluster updates
    for cluster_name, updates in sorted(remote_updates.items()):
        report['remote_updates'][cluster_name] = {}
        for role_name, info in sorted(updates.items()):
            report['remote_updates'][cluster_name][role_name] = {
                'patterns_to_add': sorted(list(info['patterns_to_add'])),
                'count': len(info['patterns_to_add'])
            }
    
    # CCS updates
    for role_name, info in sorted(ccs_updates.items()):
        sync_sources = {}
        for cluster, patterns in info['sources'].get('sync', {}).items():
            sync_sources[cluster] = sorted(list(patterns))
        
        report['ccs_updates'][role_name] = {
            'patterns_to_add': sorted(list(info['patterns_to_add'])),
            'count': len(info['patterns_to_add']),
            'sources': {
                'inject': sorted(list(info['sources']['inject'])),
                'sync': sync_sources
            }
        }
    
    # CCS Kibana updates
    for role_name, info in sorted(ccs_kibana_updates.items()):
        if info.get('needs_update'):
            report['ccs_kibana_updates'][role_name] = {
                'spaces': sorted(list(info['spaces'])),
                'missing_privileges': sorted(list(info['missing_privileges']))
            }
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report


def print_summary(
    remote_updates: Dict[str, Dict[str, Dict]],
    ccs_updates: Dict[str, Dict],
    ccs_kibana_updates: Dict[str, Dict],
    remote_results: Dict[str, Dict[str, bool]],
    ccs_results: Dict[str, bool],
    dry_run: bool,
    skip_remote: bool,
    skip_ccs: bool,
    skip_kibana: bool,
    remote_inject_patterns: Set[str],
    ccs_inject_patterns: Set[str],
    ccs_kibana_privileges: Set[str],
    remote_clusters: List[str],
    ccs_cluster: str
):
    """Print summary of operations"""
    logger = logging.getLogger(__name__)
    
    logger.info("\n" + "="*70)
    logger.info("SUMMARY")
    logger.info("="*70)
    
    if dry_run:
        logger.info("Mode: DRY RUN (no changes made)")
    
    logger.info(f"\nRemote cluster inject patterns: {', '.join(sorted(remote_inject_patterns))}")
    logger.info(f"CCS cluster inject patterns: {', '.join(sorted(ccs_inject_patterns))}")
    logger.info(f"CCS Kibana privileges: {', '.join(sorted(ccs_kibana_privileges)) if not skip_kibana else 'SKIPPED'}")
    logger.info(f"Remote clusters: {', '.join(remote_clusters)}")
    logger.info(f"CCS cluster: {ccs_cluster}")
    
    # Remote Cluster Summaries
    for cluster_name in remote_clusters:
        logger.info(f"\n--- {cluster_name.upper()} CLUSTER (Remote) ---")
        if skip_remote:
            logger.info("  SKIPPED")
        else:
            updates = remote_updates.get(cluster_name, {})
            results = remote_results.get(cluster_name, {})
            
            logger.info(f"  Roles to update: {len(updates)}")
            if not dry_run and results:
                successful = sum(1 for s in results.values() if s)
                logger.info(f"  Successfully updated: {successful}")
                logger.info(f"  Failed: {len(results) - successful}")
            
            if updates:
                for role_name, info in sorted(updates.items()):
                    status = ""
                    if not dry_run and role_name in results:
                        status = " ✓" if results[role_name] else " ✗"
                    patterns = info['patterns_to_add']
                    logger.info(f"    {role_name}{status}: +{len(patterns)} → {', '.join(sorted(patterns))}")
    
    # CCS Summary
    logger.info(f"\n--- {ccs_cluster.upper()} CLUSTER (CCS) ---")
    if skip_ccs:
        logger.info("  SKIPPED")
    else:
        logger.info(f"  Roles to update (patterns): {len(ccs_updates)}")
        kibana_updates_count = len([k for k, v in ccs_kibana_updates.items() if v.get('needs_update')])
        if not skip_kibana:
            logger.info(f"  Roles to update (Kibana): {kibana_updates_count}")
        
        if not dry_run and ccs_results:
            successful = sum(1 for s in ccs_results.values() if s)
            logger.info(f"  Successfully updated: {successful}")
            logger.info(f"  Failed: {len(ccs_results) - successful}")
        
        if ccs_updates or (ccs_kibana_updates and not skip_kibana):
            # Get all roles that need any update
            all_roles = set(ccs_updates.keys())
            if not skip_kibana:
                all_roles.update(k for k, v in ccs_kibana_updates.items() if v.get('needs_update'))
            
            for role_name in sorted(all_roles):
                status = ""
                if not dry_run and role_name in ccs_results:
                    status = " ✓" if ccs_results[role_name] else " ✗"
                
                # Pattern info
                pattern_info = ""
                if role_name in ccs_updates and ccs_updates[role_name]['patterns_to_add']:
                    info = ccs_updates[role_name]
                    patterns = info['patterns_to_add']
                    sources = info['sources']
                    
                    source_tags = []
                    if sources['inject']:
                        source_tags.append(f"INJ:{len(sources['inject'])}")
                    for cluster, sync_patterns in sources.get('sync', {}).items():
                        source_tags.append(f"{cluster.upper()}:{len(sync_patterns)}")
                    
                    pattern_info = f"+{len(patterns)} patterns [{', '.join(source_tags)}]"
                
                # Kibana info
                kibana_info = ""
                if not skip_kibana and role_name in ccs_kibana_updates:
                    kinfo = ccs_kibana_updates[role_name]
                    if kinfo.get('needs_update'):
                        kibana_info = f"+Kibana ({len(kinfo['spaces'])} spaces)"
                
                # Combine
                updates_str = ", ".join(filter(None, [pattern_info, kibana_info]))
                logger.info(f"    {role_name}{status}: {updates_str}")
                
                if pattern_info and role_name in ccs_updates:
                    logger.info(f"      Patterns: {', '.join(sorted(ccs_updates[role_name]['patterns_to_add']))}")
                if kibana_info and role_name in ccs_kibana_updates:
                    kinfo = ccs_kibana_updates[role_name]
                    logger.info(f"      Kibana spaces: {', '.join(sorted(kinfo['spaces']))}")
    
    logger.info("="*70)


def main():
    """Main execution function"""
    args = parse_arguments()
    
    # Setup logging
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = args.log_dir / f'role_auto_update_{timestamp}.log'
    logger = setup_logging(log_file, args.log_level)
    
    try:
        # Load configuration first (needed for --list-clusters)
        logger.info(f"Loading configuration from: {args.config}")
        config = load_config(args.config)
        
        # Handle --list-clusters
        if args.list_clusters:
            list_clusters(config)
            return 0
        
        logger.info("="*70)
        logger.info("Elasticsearch Role Auto-Updater (Multi-Cluster)")
        logger.info("="*70)
        
        # Get defaults from config
        defaults = config.get('defaults', {})
        
        # Determine remote clusters
        remote_clusters = args.remote_clusters or defaults.get('remote_clusters', [])
        if not remote_clusters and not args.skip_remote:
            logger.error("No remote clusters specified. Use --remote-clusters or set defaults in config.")
            return 1
        
        # Validate remote clusters exist
        for cluster in remote_clusters:
            if cluster not in config['clusters']:
                logger.error(f"Remote cluster '{cluster}' not found in configuration.")
                logger.error(f"Available clusters: {', '.join(config['clusters'].keys())}")
                return 1
        
        # Determine CCS cluster
        ccs_cluster = args.ccs_cluster or defaults.get('ccs_cluster')
        if not ccs_cluster and not args.skip_ccs:
            logger.error("No CCS cluster specified. Use --ccs-cluster or set defaults in config.")
            return 1
        
        if ccs_cluster and ccs_cluster not in config['clusters']:
            logger.error(f"CCS cluster '{ccs_cluster}' not found in configuration.")
            logger.error(f"Available clusters: {', '.join(config['clusters'].keys())}")
            return 1
        
        # Build inject patterns sets (different for remote vs CCS)
        remote_inject_patterns = set()
        ccs_inject_patterns = set()
        
        if not args.skip_inject:
            # Remote cluster inject patterns
            if args.remote_inject_patterns:
                remote_inject_patterns.update(args.remote_inject_patterns)
            elif defaults.get('remote_inject_patterns'):
                remote_inject_patterns.update(defaults['remote_inject_patterns'])
            else:
                remote_inject_patterns.update(DEFAULT_REMOTE_INJECT_PATTERNS)
            
            # CCS cluster inject patterns
            if args.ccs_inject_patterns:
                ccs_inject_patterns.update(args.ccs_inject_patterns)
            elif defaults.get('ccs_inject_patterns'):
                ccs_inject_patterns.update(defaults['ccs_inject_patterns'])
            else:
                ccs_inject_patterns.update(DEFAULT_CCS_INJECT_PATTERNS)
        
        # Build Kibana privileges set
        ccs_kibana_privileges = set()
        if not args.skip_kibana_privileges:
            if args.ccs_kibana_privileges:
                ccs_kibana_privileges.update(args.ccs_kibana_privileges)
            elif defaults.get('ccs_kibana_privileges'):
                ccs_kibana_privileges.update(defaults['ccs_kibana_privileges'])
            else:
                ccs_kibana_privileges.update(DEFAULT_CCS_KIBANA_PRIVILEGES)
        
        logger.info(f"\nRemote inject patterns: {', '.join(sorted(remote_inject_patterns)) if remote_inject_patterns else 'NONE'}")
        logger.info(f"CCS inject patterns: {', '.join(sorted(ccs_inject_patterns)) if ccs_inject_patterns else 'NONE'}")
        logger.info(f"CCS Kibana privileges: {', '.join(sorted(ccs_kibana_privileges)) if ccs_kibana_privileges else 'SKIPPED'}")
        logger.info(f"Remote clusters: {', '.join(remote_clusters)}")
        logger.info(f"CCS cluster: {ccs_cluster if not args.skip_ccs else 'SKIPPED'}")
        logger.info(f"Update remote: {'SKIP' if args.skip_remote else 'YES'}")
        logger.info(f"Update CCS: {'SKIP' if args.skip_ccs else 'YES'}")
        logger.info(f"Dry run: {args.dry_run}")
        logger.info(f"Log file: {log_file}")
        
        # Get role names to update
        if args.roles:
            role_names = args.roles
            logger.info(f"\nRoles specified via command line: {len(role_names)}")
        elif args.role_file:
            role_names = load_roles_from_file(args.role_file)
            logger.info(f"\nRoles loaded from file: {args.role_file}")
        elif args.all_matching:
            role_names = None  # Will be determined after fetching roles
            logger.info(f"\nMode: Update all matching roles")
        else:
            logger.error("No roles specified. Use --roles, --role-file, or --all-matching.")
            return 1
        
        # Initialize managers and fetch roles
        logger.info("\n" + "-"*70)
        logger.info("CONNECTING TO CLUSTERS")
        logger.info("-"*70)
        
        remote_managers = {}  # cluster_name -> manager
        remote_all_roles = {}  # cluster_name -> {role_name -> role_def}
        
        # Connect to remote clusters
        if not args.skip_remote or not args.skip_ccs:
            for cluster_name in remote_clusters:
                cluster_config = config['clusters'][cluster_name]
                logger.info(f"\nConnecting to {cluster_name.upper()} cluster...")
                
                manager = ElasticsearchRoleManager(
                    cluster_config['url'],
                    cluster_config['api_key'],
                    cluster_config.get('verify_ssl', False)
                )
                
                if not manager.test_connection():
                    logger.error(f"Failed to connect to {cluster_name} cluster. Exiting.")
                    return 1
                
                logger.info(f"Retrieving roles from {cluster_name}...")
                all_roles = manager.get_all_roles()
                logger.info(f"Retrieved {len(all_roles)} roles from {cluster_name}")
                
                remote_managers[cluster_name] = manager
                remote_all_roles[cluster_name] = all_roles
        
        # Connect to CCS cluster
        ccs_manager = None
        ccs_kibana_client = None
        ccs_all_roles = {}
        
        if not args.skip_ccs and ccs_cluster:
            cluster_config = config['clusters'][ccs_cluster]
            logger.info(f"\nConnecting to {ccs_cluster.upper()} (CCS) cluster...")
            
            ccs_manager = ElasticsearchRoleManager(
                cluster_config['url'],
                cluster_config['api_key'],
                cluster_config.get('verify_ssl', False)
            )
            
            if not ccs_manager.test_connection():
                logger.error(f"Failed to connect to {ccs_cluster} cluster. Exiting.")
                return 1
            
            logger.info(f"Retrieving roles from {ccs_cluster}...")
            ccs_all_roles = ccs_manager.get_all_roles()
            logger.info(f"Retrieved {len(ccs_all_roles)} roles from {ccs_cluster}")
            
            # Connect to Kibana for the CCS cluster (for checking disabled features)
            if not args.skip_kibana_privileges and cluster_config.get('kibana_url'):
                logger.info(f"Connecting to {ccs_cluster.upper()} Kibana...")
                ccs_kibana_client = KibanaClient(
                    cluster_config['kibana_url'],
                    cluster_config['api_key'],
                    cluster_config.get('verify_ssl', False)
                )
                
                if ccs_kibana_client.test_connection():
                    logger.info("Kibana connection successful (will check disabled features in spaces)")
                else:
                    logger.warning("Kibana connection failed - will fall back to required privileges only for space_read replacement")
                    ccs_kibana_client = None
            elif not args.skip_kibana_privileges:
                logger.info(f"No kibana_url configured for {ccs_cluster} - will include all features for space_read replacement")
        
        # Determine roles to process (if --all-matching)
        if args.all_matching:
            # Find roles that exist in all clusters
            all_role_sets = [set(roles.keys()) for roles in remote_all_roles.values()]
            if ccs_all_roles:
                all_role_sets.append(set(ccs_all_roles.keys()))
            
            if all_role_sets:
                common_roles = set.intersection(*all_role_sets)
                # Filter out reserved roles
                role_names = []
                for role in common_roles:
                    is_reserved = False
                    for cluster_roles in remote_all_roles.values():
                        if cluster_roles.get(role, {}).get('metadata', {}).get('_reserved'):
                            is_reserved = True
                            break
                    if not is_reserved:
                        role_names.append(role)
                logger.info(f"\nFound {len(role_names)} non-reserved roles in all clusters")
            else:
                role_names = []
        
        # Validate role names across clusters
        valid_roles = []
        invalid_roles = []
        
        for role_name in role_names:
            is_valid = True
            
            # Check in remote clusters
            if not args.skip_remote:
                for cluster_name in remote_clusters:
                    if role_name not in remote_all_roles.get(cluster_name, {}):
                        logger.warning(f"Role not found in {cluster_name}: {role_name}")
                        invalid_roles.append(f"{role_name} (not in {cluster_name})")
                        is_valid = False
                        break
            
            # Check in CCS cluster
            if is_valid and not args.skip_ccs and ccs_all_roles:
                if role_name not in ccs_all_roles:
                    logger.warning(f"Role not found in {ccs_cluster}: {role_name}")
                    invalid_roles.append(f"{role_name} (not in {ccs_cluster})")
                    is_valid = False
            
            if is_valid:
                valid_roles.append(role_name)
        
        if not valid_roles:
            logger.error("No valid roles to update. Exiting.")
            return 1
        
        logger.info(f"\nValid roles to process: {len(valid_roles)}")
        if invalid_roles:
            logger.warning(f"Invalid/missing roles: {len(invalid_roles)}")
        
        # Create backups
        if not args.no_backup:
            logger.info("\n" + "-"*70)
            logger.info("CREATING BACKUPS")
            logger.info("-"*70)
            
            if not args.skip_remote:
                for cluster_name, manager in remote_managers.items():
                    roles_to_backup = {k: v for k, v in remote_all_roles[cluster_name].items() if k in valid_roles}
                    backup_file = manager.backup_roles(
                        roles_to_backup,
                        args.backup_dir / cluster_name
                    )
                    logger.info(f"{cluster_name.upper()} backup: {backup_file}")
            
            if ccs_manager and not args.skip_ccs:
                roles_to_backup = {k: v for k, v in ccs_all_roles.items() if k in valid_roles}
                backup_file = ccs_manager.backup_roles(
                    roles_to_backup,
                    args.backup_dir / ccs_cluster
                )
                logger.info(f"{ccs_cluster.upper()} backup: {backup_file}")
        
        # Analyze roles
        logger.info("\n" + "-"*70)
        logger.info("ANALYZING ROLES")
        logger.info("-"*70)
        
        remote_updates = {cluster: {} for cluster in remote_clusters}  # cluster -> {role -> info}
        ccs_updates = {}  # role -> info
        ccs_kibana_updates = {}  # role -> kibana info
        
        for role_name in valid_roles:
            logger.info(f"\nAnalyzing: {role_name}")
            
            # Analyze remote cluster roles
            if not args.skip_remote:
                for cluster_name in remote_clusters:
                    if role_name in remote_all_roles.get(cluster_name, {}):
                        role_def = remote_all_roles[cluster_name][role_name]
                        needs_update, patterns_to_add = analyze_role_for_injection(
                            role_name, role_def, remote_inject_patterns, remote_managers[cluster_name]
                        )
                        if needs_update:
                            remote_updates[cluster_name][role_name] = {'patterns_to_add': patterns_to_add}
                            logger.info(f"  [{cluster_name.upper()}] Needs {len(patterns_to_add)} patterns: {', '.join(sorted(patterns_to_add))}")
                        else:
                            logger.info(f"  [{cluster_name.upper()}] Already has all required patterns")
            
            # Analyze CCS role
            if not args.skip_ccs and role_name in ccs_all_roles:
                ccs_role_def = ccs_all_roles[role_name]
                
                # Get remote role definitions for sync
                remote_role_defs = {}
                for cluster_name in remote_clusters:
                    remote_role_defs[cluster_name] = remote_all_roles.get(cluster_name, {}).get(role_name)
                
                # Analyze patterns
                analysis = analyze_ccs_role_for_sync(
                    role_name, ccs_role_def, remote_role_defs,
                    ccs_inject_patterns, ccs_manager, args.skip_inject
                )
                
                if analysis['patterns_to_add']:
                    ccs_updates[role_name] = analysis
                    sources = analysis['sources']
                    logger.info(f"  [{ccs_cluster.upper()}] Needs {len(analysis['patterns_to_add'])} patterns:")
                    if sources['inject']:
                        logger.info(f"    From injection: {', '.join(sorted(sources['inject']))}")
                    for cluster, patterns in sources.get('sync', {}).items():
                        logger.info(f"    From {cluster} sync: {', '.join(sorted(patterns))}")
                else:
                    logger.info(f"  [{ccs_cluster.upper()}] Already has all required patterns")
                
                # Analyze Kibana privileges
                if not args.skip_kibana_privileges and ccs_kibana_privileges:
                    kibana_analysis = analyze_ccs_role_for_kibana(
                        role_name, ccs_role_def, ccs_kibana_privileges
                    )
                    ccs_kibana_updates[role_name] = kibana_analysis
                    
                    if kibana_analysis['needs_update']:
                        logger.info(f"  [{ccs_cluster.upper()}] Needs Kibana privileges for {len(kibana_analysis['spaces'])} spaces:")
                        logger.info(f"    Spaces: {', '.join(sorted(kibana_analysis['spaces']))}")
                        logger.info(f"    Missing: {', '.join(sorted(kibana_analysis['missing_privileges']))}")
                    else:
                        if kibana_analysis['spaces']:
                            logger.info(f"  [{ccs_cluster.upper()}] Already has all Kibana privileges for {len(kibana_analysis['spaces'])} spaces")
                        else:
                            logger.info(f"  [{ccs_cluster.upper()}] No Kibana spaces assigned (skipping Kibana privileges)")
        
        # Check if any updates needed
        total_remote_updates = sum(len(updates) for updates in remote_updates.values())
        total_kibana_updates = len([k for k, v in ccs_kibana_updates.items() if v.get('needs_update')])
        
        if not total_remote_updates and not ccs_updates and not total_kibana_updates:
            logger.info("\n✓ No roles need updating. All roles are up to date.")
            print_summary(
                remote_updates, ccs_updates, ccs_kibana_updates, {}, {},
                args.dry_run, args.skip_remote, args.skip_ccs, args.skip_kibana_privileges,
                remote_inject_patterns, ccs_inject_patterns, ccs_kibana_privileges,
                remote_clusters, ccs_cluster or "N/A"
            )
            return 0
        
        logger.info(f"\nRoles needing updates:")
        for cluster_name in remote_clusters:
            logger.info(f"  {cluster_name.upper()}: {len(remote_updates.get(cluster_name, {}))}")
        if ccs_cluster:
            logger.info(f"  {ccs_cluster.upper()} (CCS patterns): {len(ccs_updates)}")
            if not args.skip_kibana_privileges:
                logger.info(f"  {ccs_cluster.upper()} (CCS Kibana): {total_kibana_updates}")
        
        # Generate report
        report_file = args.log_dir / f'role_update_report_{timestamp}.json'
        generate_report(
            remote_updates, ccs_updates, ccs_kibana_updates, report_file,
            remote_inject_patterns, ccs_inject_patterns, ccs_kibana_privileges,
            remote_clusters, ccs_cluster or "N/A"
        )
        logger.info(f"Report saved to: {report_file}")
        
        # If report-only mode, exit here
        if args.report_only:
            logger.info("\nReport-only mode: exiting without making changes")
            print_summary(
                remote_updates, ccs_updates, ccs_kibana_updates, {}, {},
                True, args.skip_remote, args.skip_ccs, args.skip_kibana_privileges,
                remote_inject_patterns, ccs_inject_patterns, ccs_kibana_privileges,
                remote_clusters, ccs_cluster or "N/A"
            )
            return 0
        
        # Perform updates
        logger.info("\n" + "="*70)
        logger.info("UPDATING ROLES")
        logger.info("="*70)
        
        remote_results = {cluster: {} for cluster in remote_clusters}
        ccs_results = {}
        
        # Update remote cluster roles
        if not args.skip_remote:
            for cluster_name in remote_clusters:
                updates = remote_updates.get(cluster_name, {})
                if not updates:
                    continue
                
                logger.info(f"\n--- Updating {cluster_name.upper()} Cluster ---")
                manager = remote_managers[cluster_name]
                
                for idx, (role_name, info) in enumerate(updates.items(), 1):
                    logger.info(f"\n[{idx}/{len(updates)}] {role_name}")
                    logger.info(f"  Adding: {', '.join(sorted(info['patterns_to_add']))}")
                    
                    success = update_single_role(
                        manager, role_name, remote_all_roles[cluster_name][role_name],
                        info['patterns_to_add'], cluster_name.upper(), args.dry_run
                    )
                    remote_results[cluster_name][role_name] = success
                    
                    if not success and not args.continue_on_error:
                        logger.error("Stopping due to error (use --continue-on-error to continue)")
                        break
        
        # Update CCS roles (patterns and Kibana)
        if not args.skip_ccs:
            # Get all roles that need any CCS update
            roles_needing_ccs_update = set(ccs_updates.keys())
            if not args.skip_kibana_privileges:
                roles_needing_ccs_update.update(
                    k for k, v in ccs_kibana_updates.items() if v.get('needs_update')
                )
            
            if roles_needing_ccs_update:
                logger.info(f"\n--- Updating {ccs_cluster.upper()} (CCS) Cluster ---")
                
                for idx, role_name in enumerate(sorted(roles_needing_ccs_update), 1):
                    logger.info(f"\n[{idx}/{len(roles_needing_ccs_update)}] {role_name}")
                    
                    patterns_to_add = set()
                    if role_name in ccs_updates:
                        patterns_to_add = ccs_updates[role_name]['patterns_to_add']
                        logger.info(f"  Adding patterns: {', '.join(sorted(patterns_to_add))}")
                    
                    kibana_update = ccs_kibana_updates.get(role_name, {'needs_update': False})
                    if kibana_update.get('needs_update'):
                        logger.info(f"  Adding Kibana privileges for spaces: {', '.join(sorted(kibana_update['spaces']))}")
                    
                    success = update_ccs_role_with_kibana(
                        ccs_manager, role_name, ccs_all_roles[role_name],
                        patterns_to_add, kibana_update, ccs_kibana_privileges,
                        ccs_cluster.upper(), args.dry_run, ccs_kibana_client
                    )
                    ccs_results[role_name] = success
                    
                    if not success and not args.continue_on_error:
                        logger.error("Stopping due to error (use --continue-on-error to continue)")
                        break
        
        # Print summary
        print_summary(
            remote_updates, ccs_updates, ccs_kibana_updates,
            remote_results, ccs_results,
            args.dry_run, args.skip_remote, args.skip_ccs, args.skip_kibana_privileges,
            remote_inject_patterns, ccs_inject_patterns, ccs_kibana_privileges,
            remote_clusters, ccs_cluster or "N/A"
        )
        
        # Return appropriate exit code
        if args.dry_run:
            return 0
        
        all_remote_success = all(
            all(results.values()) if results else True
            for results in remote_results.values()
        )
        all_ccs_success = all(ccs_results.values()) if ccs_results else True
        
        return 0 if (all_remote_success and all_ccs_success) else 1
        
    except KeyboardInterrupt:
        logger.warning("\nOperation interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"\nUnexpected error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
