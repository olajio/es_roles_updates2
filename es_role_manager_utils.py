#!/usr/bin/env python3
"""
Elasticsearch Role Manager Utilities
Shared functions for managing Elasticsearch roles with remote index patterns
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
import requests
from requests.auth import HTTPBasicAuth


class KibanaClient:
    """Client for Kibana API operations"""

    def __init__(self, kibana_url: str, api_key: str, verify_ssl: bool = True):
        """
        Initialize the Kibana client

        Args:
            kibana_url: Kibana URL (e.g., https://cluster.kb.us-central1.gcp.cloud.es.io)
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.kibana_url = kibana_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = self._create_session()
        self.logger = logging.getLogger(__name__)
        # Cache for space configurations
        self._space_cache: Dict[str, Dict] = {}

    def _create_session(self) -> requests.Session:
        """Create a requests session with appropriate headers"""
        session = requests.Session()
        session.headers.update({
            'Authorization': f'ApiKey {self.api_key}',
            'Content-Type': 'application/json',
            'kbn-xsrf': 'true'  # Required for Kibana API
        })
        session.verify = self.verify_ssl
        return session

    def test_connection(self) -> bool:
        """Test connection to Kibana"""
        try:
            response = self.session.get(f'{self.kibana_url}/api/status')
            response.raise_for_status()
            version = response.json().get('version', {}).get('number', 'unknown')
            self.logger.info(f"Successfully connected to Kibana: {version}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Kibana: {e}")
            return False

    def get_space(self, space_id: str) -> Optional[Dict]:
        """
        Get space configuration from Kibana

        Args:
            space_id: Space identifier (without 'space:' prefix)

        Returns:
            Space configuration dict or None if not found/error
        """
        # Check cache first
        if space_id in self._space_cache:
            return self._space_cache[space_id]

        try:
            response = self.session.get(f'{self.kibana_url}/api/spaces/space/{space_id}')
            response.raise_for_status()
            space_config = response.json()
            self._space_cache[space_id] = space_config
            return space_config
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                self.logger.warning(f"Space not found: {space_id}")
            else:
                self.logger.error(f"HTTP error getting space {space_id}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to get space {space_id}: {e}")
            return None

    def get_disabled_features(self, space_id: str) -> Optional[Set[str]]:
        """
        Get disabled features for a space

        Args:
            space_id: Space identifier (without 'space:' prefix)

        Returns:
            Set of disabled feature names (e.g., {'ml', 'graph'}) or None on error
        """
        space_config = self.get_space(space_id)
        if space_config is None:
            return None

        disabled = space_config.get('disabledFeatures', [])
        return set(disabled)

    def clear_cache(self):
        """Clear the space configuration cache"""
        self._space_cache.clear()


class ElasticsearchRoleManager:
    """Manager for Elasticsearch role operations with CCS support"""

    def __init__(self, es_url: str, api_key: str, verify_ssl: bool = True):
        """
        Initialize the role manager

        Args:
            es_url: Elasticsearch URL (e.g., https://localhost:9200)
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.es_url = es_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = self._create_session()
        self.logger = logging.getLogger(__name__)

    def _create_session(self) -> requests.Session:
        """Create a requests session with appropriate headers"""
        session = requests.Session()
        session.headers.update({
            'Authorization': f'ApiKey {self.api_key}',
            'Content-Type': 'application/json'
        })
        session.verify = self.verify_ssl
        return session

    def test_connection(self) -> bool:
        """Test connection to Elasticsearch"""
        try:
            response = self.session.get(f'{self.es_url}/')
            response.raise_for_status()
            self.logger.info(
                f"Successfully connected to Elasticsearch: {response.json().get('version', {}).get('number', 'unknown')}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            return False

    def get_all_roles(self) -> Dict:
        """Retrieve all roles from Elasticsearch"""
        try:
            response = self.session.get(f'{self.es_url}/_security/role')
            response.raise_for_status()
            roles = response.json()
            self.logger.info(f"Retrieved {len(roles)} roles from Elasticsearch")
            return roles
        except Exception as e:
            self.logger.error(f"Failed to retrieve roles: {e}")
            raise

    def get_role(self, role_name: str) -> Optional[Dict]:
        """Retrieve a specific role"""
        try:
            response = self.session.get(f'{self.es_url}/_security/role/{role_name}')
            response.raise_for_status()
            return response.json().get(role_name)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise
        except Exception as e:
            self.logger.error(f"Failed to retrieve role {role_name}: {e}")
            raise

    def update_role(self, role_name: str, role_definition: Dict) -> bool:
        """Update a role in Elasticsearch"""
        try:
            # Remove metadata fields that shouldn't be updated
            # - _reserved, _deprecated, _deprecated_reason: internal Elasticsearch flags
            # - transient_metadata: read-only field generated by Elasticsearch
            fields_to_remove = ['_reserved', '_deprecated', '_deprecated_reason', 'transient_metadata']
            clean_definition = {k: v for k, v in role_definition.items()
                                if k not in fields_to_remove}

            response = self.session.put(
                f'{self.es_url}/_security/role/{role_name}',
                json=clean_definition
            )
            response.raise_for_status()
            self.logger.info(f"Successfully updated role: {role_name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update role {role_name}: {e}")
            return False

    def backup_roles(self, roles: Dict, backup_dir: Path) -> Path:
        """
        Backup roles to a JSON file

        Args:
            roles: Dictionary of roles to backup
            backup_dir: Directory to store backups

        Returns:
            Path to the backup file
        """
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = backup_dir / f'roles_backup_{timestamp}.json'

        with open(backup_file, 'w') as f:
            json.dump(roles, f, indent=2)

        self.logger.info(f"Backed up {len(roles)} roles to {backup_file}")
        return backup_file

    @staticmethod
    def normalize_pattern_for_comparison(pattern: str) -> str:
        """
        Normalize a pattern for comparison purposes

        Args:
            pattern: Index pattern (may contain commas)

        Returns:
            Normalized pattern (sorted if comma-separated)

        Note: This is used for comparison only. Original order is preserved for storage.
        """
        if ',' in pattern:
            # Split, strip, sort, and rejoin for consistent comparison
            parts = [p.strip() for p in pattern.split(',')]
            return ','.join(sorted(parts))
        return pattern.strip()

    @staticmethod
    def extract_remote_patterns(role_definition: Dict) -> Set[Tuple[str, str]]:
        """
        Extract remote index patterns from a role definition

        Args:
            role_definition: Role definition dictionary

        Returns:
            Set of tuples (cluster_prefix, index_pattern)
            e.g., {('prod', 'filebeat-*'), ('qa', 'filebeat-*')}

        Note: Handles comma-separated patterns like "prod:traces-apm*,prod:logs-apm*"
              by keeping them together as "traces-apm*,logs-apm*" in ORIGINAL ORDER
        """
        remote_patterns = set()

        # Check regular indices section
        for index_entry in role_definition.get('indices', []):
            for name in index_entry.get('names', []):
                if ':' in name:
                    # Check if this is a comma-separated list of remote patterns
                    # e.g., "prod:traces-apm*,prod:logs-apm*,prod:metrics-apm*"
                    if ',' in name:
                        # Parse comma-separated remote patterns
                        parts = name.split(',')
                        cluster_prefix = None
                        local_patterns = []

                        for part in parts:
                            part = part.strip()
                            if ':' in part:
                                # Extract cluster prefix and pattern
                                cluster, pattern = part.split(':', 1)
                                if cluster_prefix is None:
                                    cluster_prefix = cluster
                                elif cluster != cluster_prefix:
                                    # Mixed clusters in comma-separated list - treat separately
                                    cluster_prefix = None
                                    break
                                local_patterns.append(pattern)

                        if cluster_prefix and local_patterns:
                            # All patterns have same cluster prefix
                            # Keep them together as comma-separated IN ORIGINAL ORDER
                            combined_pattern = ','.join(local_patterns)
                            remote_patterns.add((cluster_prefix, combined_pattern))
                        else:
                            # Mixed clusters or parsing failed - treat each separately
                            for part in parts:
                                part = part.strip()
                                if ':' in part:
                                    cluster, pattern = part.split(':', 1)
                                    remote_patterns.add((cluster, pattern))
                    else:
                        # Simple remote pattern like "prod:filebeat-*"
                        parts = name.split(':', 1)
                        if len(parts) == 2:
                            cluster_prefix, pattern = parts
                            remote_patterns.add((cluster_prefix, pattern))

        # Check remote_indices section (if exists)
        for index_entry in role_definition.get('remote_indices', []):
            for name in index_entry.get('names', []):
                # Remote indices don't have cluster prefix in the name
                # but have clusters list
                for cluster in index_entry.get('clusters', []):
                    remote_patterns.add((cluster, name))

        return remote_patterns

    @staticmethod
    def get_base_patterns(remote_patterns: Set[Tuple[str, str]]) -> Set[str]:
        """
        Extract base patterns from remote patterns

        Args:
            remote_patterns: Set of (cluster, pattern) tuples

        Returns:
            Set of base patterns (without cluster prefix), preserving original order

        Note: Preserves original order of comma-separated patterns for readability.
              Uses normalization only for deduplication.
        """
        base_patterns = set()
        seen_normalized = set()  # Track normalized versions to avoid duplicates

        for _, pattern in remote_patterns:
            pattern = pattern.strip()
            normalized = ElasticsearchRoleManager.normalize_pattern_for_comparison(pattern)

            # Only add if we haven't seen this pattern before (using normalized comparison)
            if normalized not in seen_normalized:
                base_patterns.add(pattern)  # Add original order version
                seen_normalized.add(normalized)

        return base_patterns

    @staticmethod
    def get_existing_local_patterns(role_definition: Dict) -> Set[str]:
        """
        Get existing local index patterns from a role

        Args:
            role_definition: Role definition dictionary

        Returns:
            Set of local index patterns in their original form

        Note: Returns patterns as they appear in the role (original order preserved)
        """
        local_patterns = set()

        for index_entry in role_definition.get('indices', []):
            for name in index_entry.get('names', []):
                # Local patterns don't have cluster prefix (no colon)
                if ':' not in name:
                    local_patterns.add(name.strip())

        return local_patterns

    @staticmethod
    def get_existing_local_patterns_normalized(role_definition: Dict) -> Set[str]:
        """
        Get existing local index patterns from a role in normalized form for comparison

        Args:
            role_definition: Role definition dictionary

        Returns:
            Set of normalized local index patterns (for comparison)

        Note: Normalizes comma-separated patterns by sorting for consistent comparison
        """
        local_patterns = set()

        for index_entry in role_definition.get('indices', []):
            for name in index_entry.get('names', []):
                # Local patterns don't have cluster prefix (no colon)
                if ':' not in name:
                    normalized = ElasticsearchRoleManager.normalize_pattern_for_comparison(name)
                    local_patterns.add(normalized)

        return local_patterns

    def needs_update(self, role_name: str, role_definition: Dict) -> Tuple[bool, Set[str]]:
        """
        Check if a role needs updating

        Args:
            role_name: Name of the role
            role_definition: Role definition dictionary

        Returns:
            Tuple of (needs_update, patterns_to_add)
            patterns_to_add preserves original order of comma-separated patterns
        """
        # Skip reserved roles
        if role_definition.get('metadata', {}).get('_reserved'):
            self.logger.debug(f"Skipping reserved role: {role_name}")
            return False, set()

        remote_patterns = self.extract_remote_patterns(role_definition)

        if not remote_patterns:
            self.logger.debug(f"Role {role_name} has no remote patterns")
            return False, set()

        base_patterns = self.get_base_patterns(remote_patterns)
        existing_local_normalized = self.get_existing_local_patterns_normalized(role_definition)

        # Compare using normalized patterns, but keep original order for patterns_to_add
        patterns_to_add = set()
        for pattern in base_patterns:
            normalized = self.normalize_pattern_for_comparison(pattern)
            if normalized not in existing_local_normalized:
                patterns_to_add.add(pattern)  # Keep original order

        if patterns_to_add:
            self.logger.info(f"Role {role_name} needs {len(patterns_to_add)} patterns added: {patterns_to_add}")
            return True, patterns_to_add

        return False, set()

    def _find_best_indices_entry(self, role_definition: Dict) -> Tuple[int, Optional[Dict]]:
        """
        Find the best indices entry to append patterns to

        Strategy:
        1. Look for an entry with matching privileges (read, view_index_metadata, read_cross_cluster)
        2. Prefer entries without remote patterns (no ':' in names)
        3. Fall back to the first entry if no perfect match

        Args:
            role_definition: Role definition dictionary

        Returns:
            Tuple of (index_position, entry_dict) or (-1, None) if no entries exist
        """
        indices = role_definition.get('indices', [])

        if not indices:
            return -1, None

        # Define common read privileges we're looking for
        target_privileges = {'read', 'view_index_metadata', 'read_cross_cluster'}

        best_match_idx = 0
        best_match_entry = indices[0]
        best_score = 0

        for idx, entry in enumerate(indices):
            entry_privileges = set(entry.get('privileges', []))
            score = 0

            # Score based on privilege overlap
            privilege_overlap = len(entry_privileges & target_privileges)
            score += privilege_overlap * 10

            # Bonus for entries that only have local patterns (no ':' in names)
            has_only_local = all(':' not in name for name in entry.get('names', []))
            if has_only_local:
                score += 5

            # Bonus for entries with more patterns (likely the "main" entry)
            score += len(entry.get('names', []))

            if score > best_score:
                best_score = score
                best_match_idx = idx
                best_match_entry = entry

        return best_match_idx, best_match_entry

    def add_local_patterns_to_role(self, role_definition: Dict, patterns_to_add: Set[str]) -> Dict:
        """
        Add local patterns to a role definition by appending to an existing indices entry

        Args:
            role_definition: Original role definition
            patterns_to_add: Set of patterns to add (may include comma-separated patterns)

        Returns:
            Updated role definition

        Note: This method appends patterns to an existing indices entry rather than
              creating a new entry. This keeps the role definition cleaner and more
              consistent with manual role management.
        """
        # Create a deep copy to avoid modifying the original
        updated_role = json.loads(json.dumps(role_definition))

        if not updated_role.get('indices'):
            updated_role['indices'] = []

        # Convert patterns set to list
        patterns_list = list(patterns_to_add)

        # Find the best entry to append to
        entry_idx, target_entry = self._find_best_indices_entry(updated_role)

        if entry_idx >= 0 and target_entry is not None:
            # Append patterns to existing entry's names list
            existing_names = updated_role['indices'][entry_idx].get('names', [])
            updated_role['indices'][entry_idx]['names'] = existing_names + patterns_list
            self.logger.debug(
                f"Appended {len(patterns_list)} patterns to existing indices entry at position {entry_idx}")
        else:
            # No existing entry found, create a new one with default privileges
            new_entry = {
                'names': patterns_list,
                'privileges': ['read', 'view_index_metadata', 'read_cross_cluster'],
                'allow_restricted_indices': False
            }
            updated_role['indices'].append(new_entry)
            self.logger.debug(f"Created new indices entry with {len(patterns_list)} patterns")

        return updated_role

    # =========================================================================
    # KIBANA PRIVILEGE METHODS
    # =========================================================================

    @staticmethod
    def extract_kibana_spaces(role_definition: Dict) -> Set[str]:
        """
        Extract Kibana spaces from a role's applications section
        
        Args:
            role_definition: Role definition dictionary
            
        Returns:
            Set of space identifiers (e.g., {'space:analytics', 'space:operations'})
        """
        spaces = set()
        
        for app_entry in role_definition.get('applications', []):
            # Only look at Kibana application entries
            if app_entry.get('application', '').startswith('kibana'):
                for resource in app_entry.get('resources', []):
                    # Resources are typically 'space:spacename' or '*'
                    if resource.startswith('space:') or resource == '*':
                        spaces.add(resource)
        
        return spaces

    @staticmethod
    def get_existing_kibana_privileges(role_definition: Dict, spaces: Set[str]) -> Dict[str, Set[str]]:
        """
        Get existing Kibana privileges for specific spaces
        
        Args:
            role_definition: Role definition dictionary
            spaces: Set of space identifiers to check
            
        Returns:
            Dictionary mapping space to set of privileges
        """
        privileges_by_space = {space: set() for space in spaces}
        
        for app_entry in role_definition.get('applications', []):
            if app_entry.get('application', '').startswith('kibana'):
                entry_privileges = set(app_entry.get('privileges', []))
                entry_resources = set(app_entry.get('resources', []))
                
                # Check which of our target spaces are in this entry
                matching_spaces = spaces & entry_resources
                
                # If '*' is in resources, it applies to all spaces
                if '*' in entry_resources:
                    matching_spaces = spaces
                
                for space in matching_spaces:
                    privileges_by_space[space].update(entry_privileges)
        
        return privileges_by_space

    @staticmethod
    def analyze_kibana_privileges(
        role_definition: Dict,
        required_privileges: Set[str]
    ) -> Tuple[bool, Set[str], Set[str]]:
        """
        Analyze if a role needs Kibana privilege updates
        
        Handles three scenarios:
        1. Entries with space_all: Excluded (already has full access)
        2. Entries with space_read: Included (needs to be replaced with explicit privileges)
        3. Regular feature entries: Checked for missing required privileges
        
        Args:
            role_definition: Role definition dictionary
            required_privileges: Set of privileges to ensure exist 
                               (e.g., {'feature_discover.all', 'feature_dashboard.all', 'feature_visualize.all'})
            
        Returns:
            Tuple of (needs_update, spaces_to_update, missing_privileges)
        """
        # Collect spaces and their current state
        spaces_needing_update = set()
        spaces_with_space_all = set()
        all_missing_privileges = set()
        
        # First pass: categorize all spaces
        for app_entry in role_definition.get('applications', []):
            if app_entry.get('application', '').startswith('kibana'):
                entry_privileges = set(app_entry.get('privileges', []))
                entry_resources = app_entry.get('resources', [])
                
                for resource in entry_resources:
                    if resource.startswith('space:') or resource == '*':
                        # Check for space_all - skip these spaces entirely
                        if 'space_all' in entry_privileges:
                            spaces_with_space_all.add(resource)
                        # Check for space_read - these need to be replaced
                        elif 'space_read' in entry_privileges:
                            spaces_needing_update.add(resource)
                            all_missing_privileges.update(required_privileges)
        
        # Second pass: check regular feature entries for missing privileges
        # (excluding spaces that have space_all or space_read)
        spaces_to_check = set()
        
        for app_entry in role_definition.get('applications', []):
            if app_entry.get('application', '').startswith('kibana'):
                entry_privileges = set(app_entry.get('privileges', []))
                
                # Skip entries with base space privileges
                if 'space_all' in entry_privileges or 'space_read' in entry_privileges:
                    continue
                
                entry_resources = set(app_entry.get('resources', []))
                
                for resource in entry_resources:
                    if resource.startswith('space:') or resource == '*':
                        # Skip if this space already has space_all
                        if resource not in spaces_with_space_all:
                            spaces_to_check.add(resource)
        
        # Build privileges by space for regular entries
        privileges_by_space = {space: set() for space in spaces_to_check}
        
        for app_entry in role_definition.get('applications', []):
            if app_entry.get('application', '').startswith('kibana'):
                entry_privileges = set(app_entry.get('privileges', []))
                
                # Skip entries with base space privileges
                if 'space_all' in entry_privileges or 'space_read' in entry_privileges:
                    continue
                
                entry_resources = set(app_entry.get('resources', []))
                matching_spaces = spaces_to_check & entry_resources
                
                if '*' in entry_resources:
                    matching_spaces = spaces_to_check
                
                for space in matching_spaces:
                    privileges_by_space[space].update(entry_privileges)
        
        # Check which regular spaces need updates
        for space in spaces_to_check:
            space_privileges = privileges_by_space.get(space, set())
            missing = required_privileges - space_privileges
            
            if missing:
                spaces_needing_update.add(space)
                all_missing_privileges.update(missing)
        
        needs_update = bool(spaces_needing_update)
        return needs_update, spaces_needing_update, all_missing_privileges

    # Default features to use when replacing space_read
    # Maps feature privilege prefix to Kibana's disabledFeatures short name
    SPACE_READ_REPLACEMENT_FEATURES = {
        'feature_canvas': 'canvas',
        'feature_maps': 'maps',
        'feature_ml': 'ml',
        'feature_graph': 'graph',
        'feature_logs': 'logs',
        'feature_infrastructure': 'infrastructure',
        'feature_apm': 'apm',
        'feature_uptime': 'uptime',
        'feature_slo': 'slo',
        'feature_profiling': 'profiling',
        'feature_dev_tools': 'dev_tools',
        'feature_advancedSettings': 'advancedSettings',
        'feature_indexPatterns': 'indexPatterns',
        'feature_savedObjectsManagement': 'savedObjectsManagement',
        'feature_savedObjectsTagging': 'savedObjectsTagging',
        'feature_filesManagement': 'filesManagement',
        'feature_filesSharedImage': 'filesSharedImage',
        'feature_osquery': 'osquery',
        'feature_fleet': 'fleet',
        'feature_actions': 'actions',
        'feature_stackAlerts': 'stackAlerts',
        'feature_rulesSettings': 'rulesSettings',
        'feature_maintenanceWindow': 'maintenanceWindow',
        'feature_siem': 'siem',
        'feature_securitySolutionCases': 'securitySolutionCases',
    }

    # Required features that should always be included even if disabled in space
    REQUIRED_FEATURES = {'feature_discover', 'feature_dashboard', 'feature_visualize'}

    def add_kibana_privileges_to_role(
        self,
        role_definition: Dict,
        privileges: Set[str],
        spaces: Set[str] = None,  # kept for API compatibility but not used
        kibana_client: 'KibanaClient' = None  # Optional: for checking disabled features
    ) -> Dict:
        """
        Add Kibana privileges to a role by merging into each existing Kibana application entry
        
        Handles three scenarios:
        1. Entries with space_all: Skipped (already has full access)
        2. Entries with space_read: Replaced with explicit feature privileges
           - discover, dashboard, visualize get .all (always included)
           - Other features get .read (unless disabled in space)
        3. Regular feature entries: Merged with new privileges, superseded privileges removed
        
        Args:
            role_definition: Original role definition
            privileges: Set of privileges to add 
                       (e.g., {'feature_discover.all', 'feature_dashboard.all', 'feature_visualize.all'})
            spaces: Not used - privileges are added to ALL existing Kibana entries
            kibana_client: Optional KibanaClient for checking disabled features in spaces
            
        Returns:
            Updated role definition with privileges merged into each Kibana application entry
        """
        # Create a deep copy to avoid modifying the original
        updated_role = json.loads(json.dumps(role_definition))
        
        if not updated_role.get('applications'):
            self.logger.debug("No applications section found, nothing to update")
            return updated_role
        
        # Build a set of feature prefixes that will get .all privileges
        features_getting_all = set()
        for priv in privileges:
            if priv.endswith('.all'):
                feature_prefix = priv.rsplit('.', 1)[0]
                features_getting_all.add(feature_prefix)
        
        entries_updated = 0
        entries_skipped = 0
        entries_replaced = 0
        
        # Iterate through each application entry
        for app_entry in updated_role['applications']:
            # Only process Kibana application entries
            if app_entry.get('application', '').startswith('kibana'):
                existing_privileges = set(app_entry.get('privileges', []))
                
                # Case 1: Skip entries with space_all (already has full access)
                if 'space_all' in existing_privileges:
                    entries_skipped += 1
                    self.logger.debug(
                        f"Skipping entry with space_all for resources: {app_entry.get('resources', [])}"
                    )
                    continue
                
                # Case 2: Replace space_read with explicit feature privileges
                if 'space_read' in existing_privileges:
                    new_privileges = self._build_space_read_replacement(
                        app_entry.get('resources', []),
                        privileges,
                        kibana_client
                    )
                    
                    app_entry['privileges'] = sorted(list(new_privileges))
                    entries_replaced += 1
                    
                    self.logger.debug(
                        f"Replaced space_read with {len(new_privileges)} explicit privileges "
                        f"for resources: {app_entry.get('resources', [])}"
                    )
                    continue
                
                # Case 3: Regular feature entry - merge privileges
                missing_privileges = privileges - existing_privileges
                
                if missing_privileges:
                    # Remove superseded privileges before adding .all
                    cleaned_privileges = set()
                    removed_privileges = set()
                    
                    for existing_priv in existing_privileges:
                        is_superseded = False
                        for feature_prefix in features_getting_all:
                            if existing_priv.startswith(feature_prefix + '.') and existing_priv != f"{feature_prefix}.all":
                                is_superseded = True
                                removed_privileges.add(existing_priv)
                                break
                        
                        if not is_superseded:
                            cleaned_privileges.add(existing_priv)
                    
                    # Merge new privileges into cleaned privileges list
                    merged_privileges = cleaned_privileges | privileges
                    app_entry['privileges'] = sorted(list(merged_privileges))
                    entries_updated += 1
                    
                    if removed_privileges:
                        self.logger.debug(
                            f"Removed superseded privileges: {removed_privileges} "
                            f"from entry with resources: {app_entry.get('resources', [])}"
                        )
                    self.logger.debug(
                        f"Added {len(missing_privileges)} privileges to entry "
                        f"with resources: {app_entry.get('resources', [])}"
                    )
        
        self.logger.debug(
            f"Updated {entries_updated} entries, replaced {entries_replaced} space_read entries, "
            f"skipped {entries_skipped} space_all entries"
        )
        
        return updated_role

    def _build_space_read_replacement(
        self,
        resources: List[str],
        required_privileges: Set[str],
        kibana_client: 'KibanaClient' = None
    ) -> Set[str]:
        """
        Build replacement privileges for a space_read entry
        
        Args:
            resources: List of space resources (e.g., ['space:caviar'])
            required_privileges: Set of required .all privileges
            kibana_client: Optional KibanaClient for checking disabled features
            
        Returns:
            Set of replacement privileges
        """
        new_privileges = set()
        
        # Always add required privileges (discover, dashboard, visualize .all)
        new_privileges.update(required_privileges)
        
        # Get disabled features for these spaces
        disabled_features = set()
        
        if kibana_client:
            for resource in resources:
                if resource.startswith('space:'):
                    space_id = resource.replace('space:', '')
                    space_disabled = kibana_client.get_disabled_features(space_id)
                    
                    if space_disabled is not None:
                        disabled_features.update(space_disabled)
                    else:
                        # API failed - fall back to just required privileges
                        self.logger.warning(
                            f"Failed to get disabled features for space {space_id}, "
                            f"falling back to required privileges only"
                        )
                        return new_privileges
        
        # Add .read for all other features that are not disabled
        for feature_prefix, short_name in self.SPACE_READ_REPLACEMENT_FEATURES.items():
            # Skip if this feature is disabled in the space
            if short_name in disabled_features:
                self.logger.debug(f"Skipping disabled feature: {feature_prefix} ({short_name})")
                continue
            
            # Skip if this is a required feature (already added as .all)
            if feature_prefix in self.REQUIRED_FEATURES:
                continue
            
            new_privileges.add(f"{feature_prefix}.read")
        
        return new_privileges


def setup_logging(log_file: Optional[Path] = None, log_level: str = 'INFO') -> logging.Logger:
    """
    Setup logging configuration

    Args:
        log_file: Optional path to log file
        log_level: Logging level

    Returns:
        Configured logger
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def generate_update_report(roles_to_update: Dict[str, Set[str]], output_file: Path):
    """
    Generate a report of roles that need updating

    Args:
        roles_to_update: Dictionary mapping role names to patterns that need to be added
        output_file: Path to save the report
    """
    report = {
        'timestamp': datetime.now().isoformat(),
        'total_roles': len(roles_to_update),
        'roles': {}
    }

    for role_name, patterns in sorted(roles_to_update.items()):
        report['roles'][role_name] = {
            'patterns_to_add': sorted(list(patterns)),
            'pattern_count': len(patterns)
        }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    return report
