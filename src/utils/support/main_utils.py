import datetime
import logging
import os
import re
import signal
from pathlib import Path
from typing import Dict, List, Optional

from services.system.reliability_service import reliability_manager
from shared.constants import PROJECT_ROOT
from utils.container.container_utils import PortAllocator
from utils.core.common import cleanup_containers

logger = logging.getLogger(__name__)


def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown."""

    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, cleaning up...")
        # Don't create tasks in signal handler - let the main loop handle it
        raise KeyboardInterrupt()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def parse_additional_dependencies(dep_strings: Optional[List[str]]) -> List[Dict[str, str]]:
    """Parse additional dependencies from command line arguments."""
    additional_dependencies = []

    if not dep_strings:
        return additional_dependencies

    for dep_str in dep_strings:
        try:
            parts = dep_str.split(":")
            if len(parts) == 3:
                additional_dependencies.append({"group_id": parts[0], "artifact_id": parts[1], "version": parts[2]})
            else:
                print(f"Warning: Invalid dependency format '{dep_str}', expected 'group:artifact:version'")
        except Exception as e:
            print(f"Warning: Error parsing dependency '{dep_str}': {e}")

    return additional_dependencies


def parse_cve_ids(cve_strings: Optional[List[str]]) -> Dict[str, str]:
    """
    Parse CVE IDs from command line arguments.

    Args:
        cve_strings: List of strings in format "package:CVE-ID"

    Returns:
        Dictionary mapping package names to CVE IDs
    """
    cve_mapping = {}

    if not cve_strings:
        return cve_mapping

    for cve_str in cve_strings:
        try:
            parts = cve_str.rsplit(":", 1)
            if len(parts) == 2:
                package_name = parts[0]
                cve_id = parts[1]
                logger.info(f"CVE ID is: {cve_id}")
                # Validate vulnerability ID format (CVE or GHSA)
                if not (cve_id.startswith("CVE-") or cve_id.startswith("GHSA-")):
                    print(f"Warning: Invalid vulnerability ID format '{cve_id}', expected 'CVE-YYYY-NNNN' or 'GHSA-xxxx-xxxx-xxxx'")
                    continue

                cve_mapping[package_name] = cve_id
            else:
                print(f"Warning: Invalid CVE mapping format '{cve_str}', expected 'package:CVE-ID'")
        except Exception as e:
            print(f"Warning: Error parsing CVE mapping '{cve_str}': {e}")

    return cve_mapping


def configure_llm_enhancements(enable_enhancements: bool, timeout: int):
    """Configure LLM enhancement environment variables."""
    if enable_enhancements:
        os.environ["ENABLE_LLM_EXPLOITATION_GUIDANCE"] = "true"
        os.environ["ENABLE_LLM_SIMILARITY_ANALYSIS"] = "true"
        os.environ["ENABLE_LLM_FRAMEWORK_DETECTION"] = "true"

    if timeout:
        os.environ["LLM_EXPLOITATION_TIMEOUT"] = str(timeout)
        os.environ["LLM_SIMILARITY_TIMEOUT"] = str(timeout + 15)
        os.environ["LLM_FRAMEWORK_TIMEOUT"] = str(timeout - 10)


def setup_logging(debug: bool):
    """
    Setup logging configuration.

    All INFO, WARNING, and ERROR logs go to the log file.
    Console is left clean - use print() statements for console output.
    """
    log_dir = PROJECT_ROOT / "logs"
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(log_dir, f"gyros_{timestamp}.log")

    log_level = logging.DEBUG if debug else logging.INFO

    # Clear all loggers' handlers
    for name in logging.root.manager.loggerDict:
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.setLevel(logging.NOTSET)
        logger.propagate = True

    # Clear root handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Configure formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)-8s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Create file handler - captures ALL logs (INFO, WARNING, ERROR, DEBUG)
    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)

    # Configure root logger - file only, no console handler
    logging.root.setLevel(log_level)
    logging.root.addHandler(file_handler)

    # Print to console (not logged) for user visibility
    logger.info(f"Logging initialized: {log_filename}")
    if debug:
        logger.info("Debug mode enabled - verbose logging to file")


def log_workflow_summary(workflow_results: Dict[str, any]):
    """Print workflow execution summary."""
    logger.info(f"\n{'=' * 50}")
    logger.info("WORKFLOW SUMMARY")
    logger.info(f"{'=' * 50}")
    logger.info(f"Blueprints created: {workflow_results['blueprints_created']}")
    logger.info(f"Containers built: {workflow_results['containers_built']}")
    logger.info(f"Containers running: {workflow_results['containers_running']}")

    if workflow_results["port_allocations"]:
        logger.info("\nPort allocations:")
        for container, port in workflow_results["port_allocations"].items():
            logger.info(f"  {container} → http://localhost:{port}")

    if workflow_results["errors"]:
        logger.info("\nErrors encountered:")
        for error in workflow_results["errors"]:
            logger.info(f"  ✗ {error}")


async def handle_container_workflow_with_validation(system, container_results: List[Dict], port_range: str = "8080-8090", keep_containers: bool = False) -> bool:
    """Handle container workflow with integrated exploit validation instead of monitoring."""
    if not container_results:
        print("No containers to run.")
        return True  # No containers to test is considered success

    logger = logging.getLogger(__name__)
    validation_success = True

    try:
        # Run containers and perform exploit validation for each
        for container_result in container_results:
            container_name = container_result.get("container_name")
            blueprint_id = container_result.get("blueprint_id")

            if not container_name or not blueprint_id:
                logger.error(f"Missing container info: name={container_name}, blueprint_id={blueprint_id}")
                validation_success = False
                continue

            logger.info(f"\nRunning exploit validation for {container_name}...")
            logger.info("Starting container for validation...")

            try:
                # First, start the container so it's running for validation
                port_allocator = PortAllocator(port_range)
                allocated_port = port_allocator.allocate_port()
                
                if not allocated_port:
                    print(f"No available ports for {container_name}")
                    validation_success = False
                    continue
                
                # Start the container
                ports = [f"{allocated_port}:8080"]
                run_result = await system.run_container(container_name, ports, blueprint_id)
                
                if run_result["status"] != "success":
                    print(f"Failed to start container: {run_result.get('error', 'Unknown error')}")
                    validation_success = False
                    continue
                
                # Create container info for validation
                container_info = {
                    "container_name": container_name,
                    "container_id": run_result.get("container_id"),
                    "id": run_result.get("container_id"),
                    "port": allocated_port,
                    "blueprint_id": blueprint_id,
                    "access_url": f"http://localhost:{allocated_port}",
                    "provided_by_workflow": True
                }

                logger.info(f"Container running on port {allocated_port}")
                logger.info("Testing HTTP endpoints...")
                logger.info("Collecting vulnerability indicators...")

                # Run exploit validation with the running container
                validation_result = await system.validate_exploit(blueprint_id, container_info)

                if validation_result.success and validation_result.vulnerability_demonstrated:
                    logger.info("Vulnerability successfully validated")
                    logger.info(f"Execution time: {validation_result.execution_time:.1f}s")
                    if validation_result.exploitation_indicators:
                        logger.info(f"Indicators found: {len(validation_result.exploitation_indicators)}")
                        # Filter out repetitive security header indicators
                        unique_indicators = []
                        seen_indicators = set()
                        for indicator in validation_result.exploitation_indicators:
                            if "missing_security_headers" not in indicator and indicator not in seen_indicators:
                                unique_indicators.append(indicator)
                                seen_indicators.add(indicator)
                            elif "missing_security_headers" in indicator and "missing_security_headers" not in seen_indicators:
                                unique_indicators.append("missing_security_headers: x-frame-options, content-security-policy, x-xss-protection")
                                seen_indicators.add("missing_security_headers")
                        
                        for indicator in unique_indicators[:3]:  # Show first 3 unique
                            logger.info(f"    - {indicator}")
                    if keep_containers:
                        logger.info("Container kept running for debugging (--keep-containers flag)")
                    else:
                        logger.info("Cleaning up validation container...")
                else:
                    logger.error(f"Validation failed: {validation_result.error_message or 'Unknown error'}")
                    logger.error(f"Validation failed for {blueprint_id}: {validation_result.error_message}")
                    validation_success = False

            except Exception as e:
                logger.error(f"Validation error: {str(e)}")
                logger.error(f"Exception during validation of {blueprint_id}: {e}")
                validation_success = False

        if validation_success:
            logger.info("\nAll validations completed successfully!")
            logger.info("Monitoring data saved to data/monitoring/")
        else:
            logger.warning("\nSome validations failed. Check logs for details.")

        return validation_success

    except Exception as e:
        logger.error(f"Critical error in validation workflow: {e}")
        print(f"Critical error: {str(e)}")
        return False


def validate_command_args(args) -> bool:
    """Validate command line arguments for specific commands."""
    if args.command in ["details", "regenerate", "container"] and not args.id:
        print(f"Error: Blueprint ID (--id) is required for '{args.command}' command.")
        return False

    if args.command == "containers" and not args.filter:
        print("Error: Package filter (--filter) is required for 'containers' command.")
        return False

    if args.command == "guided-process" and not args.packages:
        print("Error: At least one package is required for 'guided-process' command.")
        return False

    return True


def execute_health_commands(args) -> int:
    """Execute health-related commands."""
    if args.command == "health-check":
        health_status = reliability_manager.get_system_health()

        print("System Health Status")
        print("=" * 50)
        print(f"Overall Status: {health_status['overall_status'].upper()}")

        if health_status["circuit_breakers"]:
            print("\nCircuit Breaker Status:")
            for service, status in health_status["circuit_breakers"].items():
                print(f"  {service}: {status['state'].upper()}")
                print(f"    Success Rate: {status['success_rate']:.2%}")
                print(f"    Total Calls: {status['total_calls']}")
                if status["consecutive_failures"] > 0:
                    print(f"    Consecutive Failures: {status['consecutive_failures']}")

        return 0 if health_status["overall_status"] == "healthy" else 1

    elif args.command == "reliability-status":
        print("Detailed Reliability Status")
        print("=" * 50)

        for name, cb in reliability_manager.circuit_breakers.items():
            print(f"\nService: {name}")
            print(f"  State: {cb.state.value}")
            print(f"  Success Rate: {cb.metrics.success_rate():.2%}")
            print(f"  Average Response Time: {cb.metrics.average_response_time:.2f}s")
            print(f"  Total Calls: {cb.metrics.total_calls}")
            print(f"  Consecutive Failures: {cb.metrics.consecutive_failures}")

        return 0

    return 0


async def execute_stop_commands(args) -> int:
    """Execute container stop commands."""
    if args.command == "stop-all":
        from shared.container_state import container_state_manager
        running_containers = container_state_manager.get_running_containers()

        if running_containers:
            await cleanup_containers()
            print("All containers stopped.")
        else:
            print("No running containers to stop.")

    return 0


def execute_template_validation() -> int:
    """Execute template validation command."""

    print("Template Validation Report")
    print("=" * 50)

    # Path to templates directory
    templates_dir = Path("src/templates")

    if not templates_dir.exists():
        print("Templates directory not found!")
        return 1

    validation_results = {
        "vulnerability_templates": [],
        "import_templates": [],
        "framework_templates": [],
        "container_templates": [],
        "errors": [],
        "warnings": [],
    }

    # Validate vulnerability templates
    vuln_dir = templates_dir / "vulnerability"
    if vuln_dir.exists():
        print(f"\nVulnerability Templates ({vuln_dir})")
        for template_file in vuln_dir.glob("*.txt"):
            result = _validate_vulnerability_template(template_file)
            validation_results["vulnerability_templates"].append(result)
            print(f"  {'✅' if result['valid'] else '❌'} {template_file.name}")
            if not result["valid"]:
                for error in result["errors"]:
                    print(f"{error}")

    # Validate import templates
    import_dir = templates_dir / "imports"
    if import_dir.exists():
        print(f"\nImport Templates ({import_dir})")
        for template_file in import_dir.glob("*.txt"):
            result = _validate_import_template(template_file)
            validation_results["import_templates"].append(result)
            print(f"  {'✅' if result['valid'] else '❌'} {template_file.name}")
            if not result["valid"]:
                for error in result["errors"]:
                    print(f"{error}")

    # Validate framework templates
    framework_dir = templates_dir / "framework"
    if framework_dir.exists():
        print(f"\nFramework Templates ({framework_dir})")
        for template_file in framework_dir.glob("*.txt"):
            result = _validate_framework_template(template_file)
            validation_results["framework_templates"].append(result)
            print(f"  {'✅' if result['valid'] else '❌'} {template_file.name}")
            if not result["valid"]:
                for error in result["errors"]:
                    print(f"{error}")

    # Validate container templates
    container_dir = templates_dir / "container"
    if container_dir.exists():
        print(f"\nContainer Templates ({container_dir})")
        for template_file in container_dir.rglob("*.txt"):
            result = _validate_container_template(template_file)
            validation_results["container_templates"].append(result)
            relative_path = template_file.relative_to(container_dir)
            print(f"  {'✅' if result['valid'] else '❌'} {relative_path}")
            if not result["valid"]:
                for error in result["errors"]:
                    print(f"⚠️{error}")

    # Summary
    print("\nValidation Summary")
    print("=" * 30)

    total_templates = (
        len(validation_results["vulnerability_templates"])
        + len(validation_results["import_templates"])
        + len(validation_results["framework_templates"])
        + len(validation_results["container_templates"])
    )

    valid_templates = sum(
        [
            sum(1 for t in validation_results["vulnerability_templates"] if t["valid"]),
            sum(1 for t in validation_results["import_templates"] if t["valid"]),
            sum(1 for t in validation_results["framework_templates"] if t["valid"]),
            sum(1 for t in validation_results["container_templates"] if t["valid"]),
        ]
    )

    invalid_templates = total_templates - valid_templates

    print(f"Total Templates: {total_templates}")
    print(f"Valid: {valid_templates}")
    print(f"Invalid: {invalid_templates}")
    print(
        f"Success Rate: {(valid_templates / total_templates * 100):.1f}%"
        if total_templates > 0
        else "No templates found"
    )

    if invalid_templates > 0:
        print(f"\n{invalid_templates} template(s) need attention!")
        return 1
    else:
        print("\nAll templates are valid!")
        return 0


def _validate_vulnerability_template(template_file: Path) -> dict:
    """Validate a vulnerability template file."""
    result = {"file": template_file.name, "valid": True, "errors": []}

    try:
        content = template_file.read_text(encoding="utf-8")

        # Check required sections
        required_sections = ["# METADATA", "# IMPORTS", "# DEMO_CODE", "# EXPLOITATION", "# MITIGATION"]
        for section in required_sections:
            if section not in content:
                result["errors"].append(f"Missing required section: {section}")
                result["valid"] = False

        # Check metadata fields
        if "# METADATA" in content:
            metadata_section = content.split("# IMPORTS")[0]
            required_metadata = ["vulnerability_type:", "severity:", "description:"]
            for field in required_metadata:
                if field not in metadata_section:
                    result["errors"].append(f"Missing metadata field: {field}")
                    result["valid"] = False

        # Check for Java imports
        if "# IMPORTS" in content:
            imports_section = content.split("# DEMO_CODE")[0]
            if "import " not in imports_section:
                result["errors"].append("No import statements found in IMPORTS section")
                result["valid"] = False

        # Check for demo code
        if "# DEMO_CODE" in content:
            demo_section = content.split("# EXPLOITATION")[0].split("# DEMO_CODE")[1]
            if len(demo_section.strip()) < 50:
                result["errors"].append("DEMO_CODE section appears to be too short")
                result["valid"] = False

        # Check for educational content
        if "# EXPLOITATION" not in content or "# MITIGATION" not in content:
            result["errors"].append("Missing educational sections (EXPLOITATION or MITIGATION)")
            result["valid"] = False

    except Exception as e:
        result["errors"].append(f"Error reading template: {str(e)}")
        result["valid"] = False

    return result


def _validate_import_template(template_file: Path) -> dict:
    """Validate an import template file."""
    result = {"file": template_file.name, "valid": True, "errors": []}

    try:
        content = template_file.read_text(encoding="utf-8")

        # Check for import statements
        if "import " not in content:
            result["errors"].append("No import statements found")
            result["valid"] = False

        # Check for valid Java import syntax
        lines = content.strip().split("\n")
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("//"):
                if not (line.startswith("import ") and line.endswith(";")):
                    result["errors"].append(f"Invalid import syntax: {line}")
                    result["valid"] = False

    except Exception as e:
        result["errors"].append(f"Error reading template: {str(e)}")
        result["valid"] = False

    return result


def _validate_framework_template(template_file: Path) -> dict:
    """Validate a framework template file."""
    result = {"file": template_file.name, "valid": True, "errors": []}

    try:
        content = template_file.read_text(encoding="utf-8")

        # Special validation for detection_patterns.txt
        if template_file.name == "detection_patterns.txt":
            # Check for framework sections
            if not re.search(r"\[.*\]", content):
                result["errors"].append("No framework sections found (missing [FRAMEWORK_NAME] headers)")
                result["valid"] = False

        # For dependency templates
        elif "dependencies" in template_file.name:
            # Check for dependency entries
            if len(content.strip()) < 10:
                result["errors"].append("Dependency template appears to be empty or too short")
                result["valid"] = False

        # General validation
        if len(content.strip()) == 0:
            result["errors"].append("Template file is empty")
            result["valid"] = False

    except Exception as e:
        result["errors"].append(f"Error reading template: {str(e)}")
        result["valid"] = False

    return result


def _validate_container_template(template_file: Path) -> dict:
    """Validate a container template file."""
    result = {"file": str(template_file), "valid": True, "errors": []}

    try:
        content = template_file.read_text(encoding="utf-8")

        # For POM templates
        if template_file.name.endswith(".txt") and "pom" in str(template_file):
            # Check for Maven XML structure
            if "<groupId>" not in content or "<artifactId>" not in content:
                result["errors"].append("Missing required Maven coordinates in POM template")
                result["valid"] = False

            # Check for template variables
            if "{" not in content or "}" not in content:
                result["errors"].append("No template variables found in POM template")
                result["valid"] = False

        # General validation
        if len(content.strip()) == 0:
            result["errors"].append("Template file is empty")
            result["valid"] = False

    except Exception as e:
        result["errors"].append(f"Error reading template: {str(e)}")
        result["valid"] = False

    return result
