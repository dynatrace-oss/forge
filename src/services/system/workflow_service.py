import logging
from typing import Any, Dict, List

from utils.container.container_utils import PortAllocator

logger = logging.getLogger(__name__)


class WorkflowService:
    """
    Service for managing workflows and container execution pipelines.
    """

    def __init__(self, system):
        """Initialize with reference to CVEEmulatorSystem."""
        self.system = system
        self.logger = logger

    async def enhanced_process_workflow(
        self,
        packages: List[str],
        limit: int,
        cve_ids: Dict[str, str] | None = None,
        auto_run: bool = False,
        port_range: str = "8080-8090",
        validate: bool = False,
        background: bool = False,
        additional_dependencies: List[Dict[str, str]] = None,
        framework_type: str = None,
    ) -> Dict[str, Any]:
        """
        Process workflow with automatic container execution.

        Args:
            packages: List of packages to process
            limit: Limit per package
            auto_run: Whether to automatically run containers
            port_range: Port range for container allocation
            validate: Whether to automatically validate exploits after building containers
            background: Whether to run containers in background
            additional_dependencies: Additional Maven dependencies
            framework_type: Force specific framework type

        Returns:
            Dictionary with workflow results
        """
        workflow_results = {
            "blueprints_created": 0,
            "containers_built": 0,
            "containers_running": 0,
            "port_allocations": {},
            "errors": [],
            "validation_tasks": [],
        }

        try:
            # Step 1: Process packages to create blueprints
            logger.info(f"Processing {len(packages)} packages with limit {limit}")

            if additional_dependencies or framework_type:
                results = await self.system.process_packages_guided(
                    packages, limit, cve_ids, additional_dependencies, framework_type
                )
            else:
                results = await self.system.process_packages(packages, limit, cve_ids)

            all_blueprints = []
            for package, blueprints in results.items():
                logger.info(f"\nPackage: {package}")
                if not blueprints:
                    logger.info("  No blueprints created.")
                    continue

                workflow_results["blueprints_created"] += len(blueprints)
                all_blueprints.extend(blueprints)

                for bp in blueprints:
                    logger.info(f"  Blueprint: {bp.name} (ID: {bp.blueprint_id})")
                    logger.info(f"    CVE: {', '.join(bp.cve_ids)}")
                    logger.info(f"    Tags: {', '.join(bp.tags)}")

            if not all_blueprints:
                logger.info("\nNo blueprints created. Exiting workflow.")
                return workflow_results

            # Step 2: Build containers
            logger.info(f"\nBuilding containers for {len(all_blueprints)} blueprints...")

            port_allocator = PortAllocator(port_range)
            container_results = []

            for bp in all_blueprints:
                logger.info(f"\nBuilding container for {bp.name}...")
                result = await self.system.build_container(bp.blueprint_id)

                if result["status"] == "success":
                    workflow_results["containers_built"] += 1
                    container_results.append(result)
                    logger.info(f"Container built: {result['container_name']}")
                else:
                    error_msg = f"Container build failed for {bp.name}: {result.get('error', 'Unknown error')}"
                    workflow_results["errors"].append(error_msg)
                    logger.error(f" {error_msg}")

            # Step 3: Automatic container execution (if requested)
            if auto_run and container_results:
                logger.info(f"\nStarting {len(container_results)} containers...")

                execution_results = await self.run_containers_with_validateing(
                    container_results, port_allocator, validate, background
                )

                workflow_results["containers_running"] = execution_results["running_count"]
                workflow_results["port_allocations"] = execution_results["port_allocations"]
                workflow_results["errors"].extend(execution_results["errors"])
                workflow_results["validation_tasks"] = execution_results["validation_tasks"]

            elif container_results:
                logger.info("\nContainers built successfully. Use --auto-run to start them automatically.")
                logger.info("Manual run commands:")
                for result in container_results:
                    logger.info(f"  podman run --rm -p 8080:8080 {result['container_name']}")

            return workflow_results

        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            workflow_results["errors"].append(str(e))
            return workflow_results

    async def run_containers_with_validateing(
        self, container_results: List[Dict], port_allocator: PortAllocator, validate: bool, background: bool
    ) -> Dict[str, Any]:
        """
        Run containers with port management and validateing.

        Args:
            container_results: Results from container builds
            port_allocator: Port allocation manager
            validate: Whether to validate containers
            background: Whether to run in background

        Returns:
            Dictionary with execution results
        """
        from shared.container_state import container_state_manager
        running_containers = container_state_manager.get_running_containers()

        execution_results = {"running_count": 0, "port_allocations": {}, "errors": [], "validation_tasks": []}

        for result in container_results:
            container_name = result["container_name"]

            # Determine container type for health validateing
            container_type = "standalone"  # Default
            if result.get("blueprint_name"):
                blueprint_name = result["blueprint_name"].lower()
                if any(fw in blueprint_name for fw in ["spring", "struts", "jenkins"]):
                    container_type = "web-app"

            try:
                # Allocate port for this container
                allocated_port = port_allocator.allocate_port()
                if not allocated_port:
                    error_msg = f"No available ports for {container_name}"
                    execution_results["errors"].append(error_msg)
                    logger.error(f"  ✗ {error_msg}")
                    continue

                # Run container with allocated port
                ports = [f"{allocated_port}:8080"]  # Default internal port mapping
                blueprint_id = result.get("blueprint_id")
                run_result = await self.system.run_container(container_name, ports, blueprint_id)

                if run_result["status"] == "success":
                    execution_results["running_count"] += 1
                    execution_results["port_allocations"][container_name] = allocated_port

                    container_info = {
                        "name": container_name,
                        "id": run_result["container_id"],
                        "port": allocated_port,
                        "stop_command": run_result["stop_command"],
                        "type": container_type,
                        "blueprint_id": result.get("blueprint_id"),  # Add blueprint_id for validation
                    }
                    running_containers[container_name] = container_info

                    logger.info(f"{container_name} running on port {allocated_port}")
                    logger.info(f"Container ID: {run_result['container_id']}")
                    logger.info(f"Access: http://localhost:{allocated_port}")

                    if validate:
                        # Start validation task using exploit validation service
                        blueprint_id = container_info.get("blueprint_id")
                        if blueprint_id:
                            # Enhanced container info for validation service
                            validation_container_info = {
                                "container_name": container_name,
                                "container_id": run_result["container_id"],
                                "id": run_result["container_id"],  # Alternative key for validation service
                                "port": allocated_port,
                                "blueprint_id": blueprint_id,
                                "stop_command": run_result["stop_command"],
                                "type": container_type,
                                "access_url": f"http://localhost:{allocated_port}",
                                "provided_by_workflow": True,  # Flag to indicate this came from workflow
                            }
                            
                            self.logger.info(f"VALIDATION HANDOFF: Passing container info to validation service for {container_name}")
                            self.logger.info(f"Container info: {validation_container_info}")
                            
                            validation_task = await self.system.exploit_validation_service.validate_vulnerability_demo(
                                blueprint_id, validation_container_info
                            )
                            execution_results["validation_tasks"].append(validation_task)
                            
                            # Log validation results
                            if validation_task.success:
                                logger.info(f"Validation completed successfully for {container_name}")
                                if validation_task.vulnerability_demonstrated:
                                    logger.info("Vulnerability successfully demonstrated")
                                else:
                                    logger.warning("Vulnerability not demonstrated but validation ran")
                            else:
                                logger.error(f"Validation failed for {container_name}: {validation_task.error_message}")
                        else:
                            logger.warning(f"No blueprint ID found for {container_name}, skipping validation")

                else:
                    port_allocator.release_port(allocated_port)
                    error_msg = f"Failed to start {container_name}: {run_result.get('error', 'Unknown error')}"
                    execution_results["errors"].append(error_msg)
                    logger.error(f"{error_msg}")

            except Exception as e:
                error_msg = f"Exception starting {container_name}: {str(e)}"
                execution_results["errors"].append(error_msg)
                logger.error(f"{error_msg}")

        # Print summary
        if execution_results["running_count"] > 0:
            logger.info(f"\n{execution_results['running_count']} containers running successfully!")
            logger.info("\nRunning containers:")
            for container in running_containers.values():
                container_type_label = f" ({container.get('type', 'unknown')})" if "type" in container else ""
                logger.info(f"{container['name']} → http://localhost:{container['port']}{container_type_label}")

            if background:
                logger.info("\nContainers running in background. Use 'podman ps' to check status.")
            else:
                logger.info("\nPress Ctrl+C to stop all containers and exit")

        return execution_results

    async def process_enhanced_workflow(
        self,
        packages: List[str],
        limit: int,
        cve_ids: Dict[str, str] | None = None,
        additional_dependencies: List[Dict[str, str]] = None,
        auto_build: bool = False,
        auto_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Process packages with enhanced guided workflow.

        Args:
            packages: List of packages to process
            limit: Limit per package
            additional_dependencies: Additional Maven dependencies
            auto_build: Whether to automatically build containers
            auto_run: Whether to automatically run containers

        Returns:
            Dictionary with workflow results
        """
        try:
            # Use guided processing if dependencies provided
            if additional_dependencies:
                results = await self.system.process_packages_guided(packages, limit, cve_ids, additional_dependencies)
            else:
                results = await self.system.process_packages(packages, limit, cve_ids)

            workflow_results = {"blueprints": results, "containers": {}, "running": {}, "errors": []}

            if auto_build:
                # Build containers for all blueprints
                for package, blueprints in results.items():
                    workflow_results["containers"][package] = []

                    for bp in blueprints:
                        try:
                            container_result = await self.system.build_container(bp.blueprint_id)
                            workflow_results["containers"][package].append(container_result)

                            if auto_run and container_result["status"] == "success":
                                # Auto-run the container
                                run_result = await self.system.run_container(
                                    container_result["container_name"], ["8080:8080"], bp.blueprint_id
                                )
                                workflow_results["running"][bp.blueprint_id] = run_result

                        except Exception as e:
                            workflow_results["errors"].append(f"Error with {bp.name}: {str(e)}")

            return workflow_results

        except Exception as e:
            logger.error(f"Workflow failed: {e}")
            return {"blueprints": {}, "containers": {}, "running": {}, "errors": [str(e)]}
