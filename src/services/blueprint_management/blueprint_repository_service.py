import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path

import aiofiles

from models.blueprint import Blueprint
from services.system.reliability_service import CircuitOpenError, reliability_manager
from shared.constants import DEFAULT_BLUEPRINT_STORAGE_DIR
from utils.core.common import (
    generate_safe_id,
    standardize_package_name,
)
from utils.error_handling.decorators import with_error_recovery

logger = logging.getLogger(__name__)


class BlueprintRepositoryService:
    """
    Service for storing and retrieving vulnerability blueprints.
    Acts as a persistence layer for the Blueprint Management Agent.
    """

    def __init__(self):
        """
        Initialize the blueprint repository service.

        Args:
            storage_dir: Directory to store blueprints (defaults to data/blueprints)
        """
        # Change this path construction to use proper path handling
        self.storage_dir = Path(DEFAULT_BLUEPRINT_STORAGE_DIR)

        # Ensure storage directory exists
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # In-memory index of blueprints for faster lookups
        self.blueprint_index: dict[str, dict[str, any]] = {}

        # Load existing blueprints into memory
        self._load_blueprint_index()
        self.reliability_manager = reliability_manager

    @with_error_recovery()
    def _load_blueprint_index(self) -> None:
        """Load existing blueprint metadata into memory for faster lookups."""
        # Reset the index
        self.blueprint_index = {}

        # Scan the storage directory for blueprint files
        for filename in os.listdir(self.storage_dir):
            if filename.endswith(".json"):
                try:
                    filepath = os.path.join(self.storage_dir, filename)
                    with open(filepath, "r", encoding="utf-8") as f:
                        blueprint_data = json.load(f)

                    # Extract blueprint ID
                    blueprint_id = blueprint_data.get("blueprint_id")
                    if not blueprint_id:
                        # Try to extract from filename if not in data
                        blueprint_id = filename.replace(".json", "")

                    # Store minimal metadata in the index
                    self.blueprint_index[blueprint_id] = {
                        "id": blueprint_id,
                        "name": blueprint_data.get("name", "Unnamed"),
                        "package": blueprint_data.get("package_name", "Unknown"),
                        "version": blueprint_data.get("package_version", "Unknown"),
                        "cve_ids": blueprint_data.get("cve_ids", []),
                        "tags": blueprint_data.get("tags", []),
                        "file_path": filepath,
                        "created_at": blueprint_data.get("created_at"),
                        "updated_at": blueprint_data.get("updated_at"),
                    }
                except Exception as e:
                    logger.error(f"Error loading blueprint from {filename}: {e}")

    @with_error_recovery(default_return={"success": False, "error": "Operation failed"})
    async def store_blueprint(self, blueprint: Blueprint) -> dict[str, any]:
        """
        Store a blueprint with atomic operations.

        Args:
            blueprint: Blueprint to store

        Returns:
            dictionary with storage result
        """
        async with self.reliability_manager.atomic_operation(f"store_blueprint_{blueprint.blueprint_id}"):
            # Ensure the blueprint has an ID
            if not blueprint.blueprint_id:
                blueprint.blueprint_id = generate_safe_id()

            # Set timestamps
            if not blueprint.created_at:
                blueprint.created_at = datetime.now()

            blueprint_dict = blueprint.to_dict()
            file_path = os.path.join(self.storage_dir, f"{blueprint.blueprint_id}.json")

            # Create backup of existing file if it exists
            backup_path = None
            if os.path.exists(file_path):
                backup_path = f"{file_path}.backup"
                shutil.copy2(file_path, backup_path)
                logger.debug(f"Created backup: {backup_path}")

            # Write to temporary file first
            temp_path = f"{file_path}.tmp"
            try:
                async with aiofiles.open(temp_path, "w", encoding="utf-8") as f:
                    await f.write(json.dumps(blueprint_dict, indent=2))

                # Atomic move
                os.rename(temp_path, file_path)
                logger.debug(f"Atomically wrote blueprint to {file_path}")

                # Update the in-memory index only after successful write
                self.blueprint_index[blueprint.blueprint_id] = {
                    "id": blueprint.blueprint_id,
                    "name": blueprint.name,
                    "package": blueprint.package_name,
                    "version": blueprint.package_version,
                    "cve_ids": blueprint.cve_ids,
                    "tags": blueprint.tags,
                    "file_path": file_path,
                    "created_at": blueprint_dict["created_at"],
                    "updated_at": blueprint_dict["updated_at"],
                }

                # Remove backup on success
                if backup_path and os.path.exists(backup_path):
                    os.remove(backup_path)

                logger.info(f"Successfully stored blueprint {blueprint.blueprint_id}")

                return {
                    "success": True,
                    "blueprint_id": blueprint.blueprint_id,
                    "file_path": file_path,
                }

            except Exception as write_error:
                # Cleanup temporary file
                if os.path.exists(temp_path):
                    os.remove(temp_path)

                # Restore backup if it exists
                if backup_path and os.path.exists(backup_path):
                    os.rename(backup_path, file_path)
                    logger.info("Restored backup after write failure")

                raise write_error

    @with_error_recovery(default_return=None)
    async def get_blueprint(self, blueprint_id: str) -> Blueprint | None:
        """
        Retrieve a blueprint with circuit breaker protection.

        Args:
            blueprint_id: ID of the blueprint to retrieve

        Returns:
            Blueprint object or None if not found
        """
        circuit_breaker = self.reliability_manager.get_circuit_breaker("blueprint_repository")

        async def _load_blueprint():
            # Direct file check first
            direct_file_path = Path(self.storage_dir) / f"{blueprint_id}.json"

            if direct_file_path.exists():
                try:
                    async with aiofiles.open(direct_file_path, "r", encoding="utf-8") as f:
                        content = await f.read()
                        blueprint_dict = json.loads(content)

                    blueprint = Blueprint.from_dict(blueprint_dict)

                    # Update index with this blueprint
                    self.blueprint_index[blueprint_id] = {
                        "id": blueprint_id,
                        "name": blueprint.name,
                        "package": blueprint.package_name,
                        "version": blueprint.package_version,
                        "cve_ids": blueprint.cve_ids,
                        "tags": blueprint.tags,
                        "file_path": str(direct_file_path),
                        "created_at": blueprint_dict.get("created_at"),
                        "updated_at": blueprint_dict.get("updated_at"),
                    }

                    return blueprint

                except json.JSONDecodeError as e:
                    logger.error(f"JSON parsing error for blueprint file {direct_file_path}: {e}")
                    return None
                except Exception as e:
                    logger.error(f"Error loading blueprint file {direct_file_path}: {e}")
                    return None

            return None

        try:
            return await circuit_breaker.call(_load_blueprint)
        except CircuitOpenError:
            logger.warning(f"Blueprint repository circuit breaker is open, cannot retrieve {blueprint_id}")
            return None

    @with_error_recovery()
    def _reload_blueprint_index(self) -> None:
        """Reload the blueprint index from storage directory."""
        logger.info(f"Reloading blueprint index from {self.storage_dir}")
        # Clear the existing index
        self.blueprint_index = {}

        # list all files in the storage directory
        if os.path.exists(self.storage_dir):
            for filename in os.listdir(self.storage_dir):
                if filename.endswith(".json"):
                    try:
                        filepath = os.path.join(self.storage_dir, filename)
                        with open(filepath, "r", encoding="utf-8") as f:
                            blueprint_data = json.load(f)

                        # Extract the blueprint ID
                        blueprint_id = blueprint_data.get("blueprint_id")
                        if not blueprint_id:
                            # Try to extract from filename if not in data
                            blueprint_id = filename.replace(".json", "")

                        # Store minimal metadata in the index
                        self.blueprint_index[blueprint_id] = {
                            "id": blueprint_id,
                            "name": blueprint_data.get("name", "Unnamed"),
                            "package": blueprint_data.get("package_name", "Unknown"),
                            "version": blueprint_data.get("package_version", "Unknown"),
                            "cve_ids": blueprint_data.get("cve_ids", []),
                            "tags": blueprint_data.get("tags", []),
                            "file_path": filepath,
                            "created_at": blueprint_data.get("created_at"),
                            "updated_at": blueprint_data.get("updated_at"),
                        }
                        logger.debug(f"Loaded blueprint {blueprint_id} into index from {filepath}")
                    except Exception as e:
                        logger.error(f"Error loading blueprint from {filename}: {e}")
        else:
            logger.warning(f"Storage directory does not exist: {self.storage_dir}")

    @with_error_recovery(default_return={"error": "Operation failed"})
    def list_all_available_blueprints(self) -> dict[str, any]:
        """list all available blueprint files for debugging."""
        result = {
            "storage_dir": str(self.storage_dir),
            "indexed_blueprints": list(self.blueprint_index.keys()),
            "blueprint_files": [],
        }

        # Check if the directory exists
        if os.path.exists(self.storage_dir):
            # list all JSON files in the directory
            files = [f for f in os.listdir(self.storage_dir) if f.endswith(".json")]
            result["blueprint_files"] = files

            # Try to extract IDs from filenames
            blueprint_ids = [f.replace(".json", "") for f in files]
            result["available_blueprint_ids"] = blueprint_ids

            # Check which indexed blueprints have valid files
            for bp_id, bp_meta in self.blueprint_index.items():
                file_path = bp_meta.get("file_path", "")
                result.setdefault("index_validation", {})[bp_id] = {
                    "file_path": file_path,
                    "exists": os.path.exists(file_path),
                }
        else:
            result["error"] = f"Storage directory does not exist: {self.storage_dir}"

        return result

    @with_error_recovery(default_return={"success": False, "error": "Operation failed"})
    async def update_blueprint(self, blueprint: Blueprint) -> dict[str, any]:
        """
        Update an existing blueprint.

        Args:
            blueprint: Updated blueprint

        Returns:
            dictionary with update result
        """
        # Check if the blueprint exists
        if blueprint.blueprint_id not in self.blueprint_index:
            return {
                "success": False,
                "error": f"Blueprint {blueprint.blueprint_id} not found",
            }

        # Get the original blueprint
        original_blueprint = await self.get_blueprint(blueprint.blueprint_id)
        if not original_blueprint:
            return {
                "success": False,
                "error": f"Blueprint {blueprint.blueprint_id} could not be loaded",
            }

        # Preserve creation timestamp
        blueprint.created_at = original_blueprint.created_at

        # Update the blueprint
        return await self.store_blueprint(blueprint)

    @with_error_recovery(default_return={"success": False, "error": "Operation failed"})
    def delete_blueprint(self, blueprint_id: str) -> dict[str, any]:
        """
        Delete a blueprint by ID.

        Args:
            blueprint_id: ID of the blueprint to delete

        Returns:
            dictionary with deletion result
        """
        # Check if the blueprint exists in the index
        if blueprint_id not in self.blueprint_index:
            return {
                "success": False,
                "error": f"Blueprint {blueprint_id} not found",
            }

        # Get the file path from the index
        file_path = self.blueprint_index[blueprint_id]["file_path"]

        # Remove the file
        os.remove(file_path)

        # Remove from the index
        del self.blueprint_index[blueprint_id]

        logger.info(f"Deleted blueprint {blueprint_id}")

        return {"success": True, "blueprint_id": blueprint_id}

    @with_error_recovery(default_return=[])
    def list_blueprints(self, package_name: str | None = None) -> list[dict[str, any]]:
        """
        list all blueprints, optionally filtered by package name.

        Args:
            package_name: Optional package name filter

        Returns:
            list of blueprint metadata dictionaries
        """
        # Standardize package name if provided
        standard_package_name = standardize_package_name(package_name) if package_name else None

        # Filter blueprints by package name if specified
        if standard_package_name:
            filtered_blueprints = []
            for blueprint in self.blueprint_index.values():
                bp_package = standardize_package_name(blueprint["package"])
                # Use partial matching for more flexible search
                if standard_package_name.lower() in bp_package.lower():
                    filtered_blueprints.append(blueprint)
        else:
            filtered_blueprints = list(self.blueprint_index.values())

        # Sort by updated_at (newest first)
        filtered_blueprints.sort(key=lambda x: x.get("updated_at", ""), reverse=True)

        return filtered_blueprints

    @with_error_recovery(default_return={"success": False, "error": "Operation failed"})
    async def get_blueprint_code_snippets(self, blueprint_id: str) -> dict[str, any]:
        """
        Get code snippets for a blueprint.

        Args:
            blueprint_id: ID of the blueprint

        Returns:
            dictionary with code snippets
        """
        # Get the blueprint
        blueprint = await self.get_blueprint(blueprint_id)
        if not blueprint:
            return {
                "success": False,
                "error": f"Blueprint {blueprint_id} not found",
            }

        # Return the code snippets
        return {
            "success": True,
            "blueprint_id": blueprint_id,
            "name": blueprint.name,
            "code_snippets": blueprint.code_snippets,
        }

    @with_error_recovery(default_return={"success": False, "error": "Operation failed"})
    async def update_code_snippets(self, blueprint_id: str, code_snippets: dict[str, str]) -> dict[str, any]:
        """
        Update code snippets for a blueprint.

        Args:
            blueprint_id: ID of the blueprint
            code_snippets: dictionary mapping file names to code content

        Returns:
            dictionary with update result
        """
        # Get the blueprint
        blueprint = await self.get_blueprint(blueprint_id)
        if not blueprint:
            return {
                "success": False,
                "error": f"Blueprint {blueprint_id} not found",
            }

        # Update the code snippets
        blueprint.code_snippets = code_snippets

        # Use blueprint's built-in update mechanism to set updated_at
        blueprint.update()

        # Store the updated blueprint
        return await self.store_blueprint(blueprint)

    @with_error_recovery(default_return={"error": "Operation failed"})
    async def get_blueprint_details(self, blueprint_id: str) -> dict[str, any]:
        """
        Get detailed information about a blueprint.

        Args:
            blueprint_id: ID of the blueprint

        Returns:
            dictionary with blueprint details
        """
        # Get the blueprint
        blueprint = await self.get_blueprint(blueprint_id)
        if not blueprint:
            return {"error": f"Blueprint {blueprint_id} not found"}

        # Convert to dictionary and return
        return blueprint.to_dict()

    @with_error_recovery(default_return={"error": "Operation failed"})
    def count_blueprints(self) -> dict[str, any]:
        """
        Get statistics about stored blueprints.

        Returns:
            dictionary with blueprint statistics
        """
        # Count by package
        package_counts: dict[str, int] = {}
        for blueprint in self.blueprint_index.values():
            package = blueprint["package"]
            if package in package_counts:
                package_counts[package] += 1
            else:
                package_counts[package] = 1

        # Count by CVE
        cve_counts: dict[str, int] = {}
        for blueprint in self.blueprint_index.values():
            for cve_id in blueprint["cve_ids"]:
                if cve_id in cve_counts:
                    cve_counts[cve_id] += 1
                else:
                    cve_counts[cve_id] = 1

        # Count by tag
        tag_counts: dict[str, int] = {}
        for blueprint in self.blueprint_index.values():
            for tag in blueprint["tags"]:
                if tag in tag_counts:
                    tag_counts[tag] += 1
                else:
                    tag_counts[tag] = 1

        # Return statistics
        # Return statistics
        return {
            "total": len(self.blueprint_index),
            "by_package": package_counts,
            "by_cve": cve_counts,
            "by_tag": tag_counts,
        }

    @with_error_recovery(default_return=[])
    async def search_blueprints(self, query: dict[str, any]) -> list[dict[str, any]]:
        """
        Search for blueprints matching specific criteria.

        Args:
            query: dictionary of search criteria
                - package_name: Package name (partial match)
                - cve_id: CVE ID (exact match)
                - tag: Tag (exact match)
                - vulnerability_type: Type of vulnerability (exact match)
                - severity: Severity level (exact match)

        Returns:
            list of matching blueprint metadata dictionaries
        """
        # Start with all blueprints
        results = list(self.blueprint_index.values())

        # Filter by package name
        if "package_name" in query and query["package_name"]:
            standard_query_package = standardize_package_name(query["package_name"])
            results = [
                bp
                for bp in results
                if standard_query_package.lower() in standardize_package_name(bp["package"]).lower()
            ]

        # Filter by CVE ID
        if "cve_id" in query and query["cve_id"]:
            results = [bp for bp in results if any(query["cve_id"] == cve for cve in bp["cve_ids"])]

        # Filter by tag
        if "tag" in query and query["tag"]:
            results = [bp for bp in results if any(query["tag"] == tag for tag in bp["tags"])]

        # For more detailed filtering, we need to load the full blueprints
        if "vulnerability_type" in query or "severity" in query:
            detailed_results = []

            for bp_meta in results:
                blueprint = await self.get_blueprint(bp_meta["id"])
                if not blueprint:
                    continue

                # Check vulnerability type
                if "vulnerability_type" in query and query["vulnerability_type"]:
                    vuln_type = blueprint.metadata.get("enhanced_metadata", {}).get("vulnerability_type", "")
                    if query["vulnerability_type"].lower() != vuln_type.lower():
                        continue

                # Check severity
                if "severity" in query and query["severity"]:
                    severity = blueprint.metadata.get("enhanced_metadata", {}).get("severity", "")
                    if query["severity"].lower() != severity.lower():
                        continue

                # Blueprint passed all filters
                detailed_results.append(bp_meta)

            results = detailed_results

        # Sort by updated_at (newest first)
        results.sort(key=lambda x: x.get("updated_at", ""), reverse=True)

        return results

    def clear_cache(self) -> None:
        """Reload the blueprint index from disk."""
        self._load_blueprint_index()
