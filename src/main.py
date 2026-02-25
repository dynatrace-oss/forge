import asyncio
import logging
import sys
from pathlib import Path

import aioconsole
import click

PROJECT_ROOT = Path(__file__).parent.parent

try:
    from dotenv import load_dotenv
    env_path = PROJECT_ROOT / ".env"
    load_dotenv(env_path)
except ImportError:
    print("Warning: python-dotenv not installed - install with: poetry add python-dotenv")
except Exception as e:
    print(f"Warning: Could not load .env file: {e}")

sys.path.insert(0, str(PROJECT_ROOT / "src"))
from utils.core.secrets_loader import load_secrets_into_environment
load_secrets_into_environment()

from services.system.system_integration_service import CVEEmulatorSystem
from services.system.workflow_service import WorkflowService
from utils.core.common import cleanup_containers, truncate_string
from utils.support.main_utils import (
    configure_llm_enhancements,
    execute_health_commands,
    execute_stop_commands,
    execute_template_validation,
    handle_container_workflow_with_validation,
    log_workflow_summary,
    parse_additional_dependencies,
    parse_cve_ids,
    setup_logging,
    setup_signal_handlers,
)

running_containers = []


def setup_cli_context(debug, config, container_dir, no_llm, enable_llm_enhancements, llm_timeout):
    """Setup CLI context and configuration."""
    setup_logging(debug)
    logger = logging.getLogger(__name__)
    logger.info("Begin protocol: Tasty Kebabs")

    setup_signal_handlers()

    # Configure LLM enhancements
    configure_llm_enhancements(enable_llm_enhancements, llm_timeout)

    return {"debug": debug, "config": config, "container_dir": container_dir, "use_llm": not no_llm}


def get_system(ctx):
    """Get or create CVEEmulatorSystem with proper event loop handling."""
    # Check if we already have a system instance in context
    if "system" not in ctx.obj:
        ctx.obj["system"] = CVEEmulatorSystem(
            config_path=ctx.obj["config"],
            container_dir=ctx.obj["container_dir"],
            use_llm=ctx.obj["use_llm"],
        )
    return ctx.obj["system"]


def coro(f):
    """Decorator to handle async functions in Click commands."""
    import functools

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@click.group()
@click.option("--debug", "-D", is_flag=True, help="Run in debug mode with additional logging")
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--container-dir", "-d", help="Directory to store container files")
@click.option("--no-llm", is_flag=True, help="Disable LLM-based container generation")
@click.option(
    "--enable-llm-enhancements", is_flag=True, help="Enable LLM enhancements for exploitation guidance and analysis"
)
@click.option("--llm-timeout", type=int, default=30, help="Timeout for LLM enhancement operations (seconds)")
@click.pass_context
def cli(ctx, debug, config, container_dir, no_llm, enable_llm_enhancements, llm_timeout):
    """FORGE Vulnerability Research Framework - CLI for automated CVE analysis and exploitation."""
    # Store context for subcommands
    ctx.ensure_object(dict)
    ctx.obj = setup_cli_context(debug, config, container_dir, no_llm, enable_llm_enhancements, llm_timeout)


@cli.command()
@click.option(
    "--packages",
    "-p",
    multiple=True,
    default=["org.yaml:snakeyaml", "net.sf.ehcache:ehcache", "com.google.guava:guava"],
    help="Packages to process",
)
@click.option("--limit", "-l", type=int, default=2, help="Limit of vulnerabilities per package")
@click.option("--additional-deps", multiple=True, help="Additional Maven dependencies (format: group:artifact:version)")
@click.option(
    "--framework-type",
    type=click.Choice(["spring-boot", "struts", "jenkins", "standalone"]),
    help="Force specific framework type for blueprint generation",
)
@click.option("--cve-ids", "-cv", multiple=True, help="Specific CVE IDs for packages (format: package:CVE-ID)")
@click.option("--auto-run", is_flag=True, help="Automatically run containers after building")
@click.option("--ports", default="8080-8090", help="Port range for container allocation")
@click.option("--validate", is_flag=True, help="Automatically validate exploits after building containers")
@click.option("--background", is_flag=True, help="Run containers in background")
@click.option("--keep-containers", is_flag=True, help="Keep containers running after validation for debugging")
@coro
@click.pass_context
async def process(
    ctx, packages, limit, additional_deps, framework_type, cve_ids, auto_run, ports, validate, background, keep_containers
):
    """Process packages and generate vulnerability blueprints with optional container building."""
    return await _process_command(
        ctx, packages, limit, additional_deps, framework_type, cve_ids, auto_run, ports, validate, background, keep_containers
    )


async def _process_command(
    ctx, packages, limit, additional_deps, framework_type, cve_ids, auto_run, _ports, _validate, _background, _keep_containers
):
    """Execute the process command with provided parameters."""
    additional_dependencies = parse_additional_dependencies(additional_deps)
    parsed_cve_ids = parse_cve_ids(cve_ids) if cve_ids else None

    system = get_system(ctx)

    global running_containers
    running_containers = []

    try:
        if additional_dependencies or framework_type:
            results = await system.process_packages_guided(
                packages, limit, parsed_cve_ids, additional_dependencies, framework_type
            )
        else:
            results = await system.process_packages(packages, limit, parsed_cve_ids)

        # Display results
        all_blueprints = []
        for package, blueprints in results.items():
            click.echo(f"\nPackage: {package}")
            if not blueprints:
                click.echo("  No blueprints created.")
                continue

            all_blueprints.extend(blueprints)
            for bp in blueprints:
                click.echo(f"  Blueprint: {bp.name} (ID: {bp.blueprint_id})")
                click.echo(f"    CVE: {', '.join(bp.cve_ids)}")
                click.echo(f"    Tags: {', '.join(bp.tags)}")
                click.echo(f"    Code Snippets: {len(bp.code_snippets)}")

        # Container building workflow
        if auto_run:
            should_build = True
        else:
            user_input = await aioconsole.ainput(
                "\nDo you want to build containers for the generated blueprints? (y/n): "
            )
            should_build = user_input.lower().startswith("y")

        if should_build:
            click.echo("\nBuilding containers...")

            container_results = []

            for package, blueprints in results.items():
                for bp in blueprints:
                    click.echo(f"\nBuilding container for {bp.name}...")
                    result = await system.build_container(bp.blueprint_id)

                    if result["status"] == "success":
                        # Ensure blueprint_id is included for validation
                        result["blueprint_id"] = bp.blueprint_id
                        container_results.append(result)
                        click.echo(f"Container built successfully: {result['container_name']}")
                    else:
                        click.echo(f"Container build failed: {result.get('error', 'Unknown error')}")
                        click.echo(f"Error details: {result.get('error', 'Unknown error')}")

            # Check if any containers failed to build
            total_blueprints = sum(len(blueprints) for blueprints in results.values())
            if len(container_results) < total_blueprints:
                click.echo(f"\nWarning: {total_blueprints - len(container_results)} containers failed to build")

            if not container_results:
                click.echo("No containers successfully built. Exiting.")
                return 1

            # Handle container execution with exploit validation
            validation_success = await handle_container_workflow_with_validation(system, container_results, _ports, _keep_containers)

            if not validation_success:
                click.echo("\nSome exploit validations failed. Check logs for details.")
                return 1

            # Return success
            return 0

        return 0

    except KeyboardInterrupt:
        await cleanup_containers(running_containers)
        click.echo("\nOperation cancelled by user.")
        return 130
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error executing process command: {e}", exc_info=True)
        click.echo(f"Error: {e}")
        return 1


@cli.command()
@click.option("--filter", "-f", help="Filter by package name")
@coro
@click.pass_context
async def list(ctx, filter):
    """List available blueprints with optional filtering."""
    system = get_system(ctx)

    blueprints = system.list_blueprints(filter)
    if not blueprints:
        click.echo("No blueprints found.")
    else:
        click.echo(f"Found {len(blueprints)} blueprints:")
        for bp in blueprints:
            click.echo(f"  {bp['name']} (ID: {bp['id']})")
            click.echo(f"    Package: {bp['package']} {bp['version']}")
            click.echo(f"    CVE: {', '.join(bp['cve_ids'])}")
            click.echo(f"    Tags: {', '.join(bp['tags'])}")
    return 0


@cli.command()
@click.option("--id", "-i", required=True, help="Blueprint ID")
@coro
@click.pass_context
async def details(ctx, id):
    """Show detailed information about a specific blueprint."""
    system = get_system(ctx)

    details = await system.get_blueprint_details(id)
    if "error" in details:
        click.echo(f"Error: {details['error']}")
        return 1

    click.echo(f"Blueprint: {details['name']} (ID: {details['blueprint_id']})")
    click.echo(f"Package: {details['package_name']} {details['package_version']}")
    click.echo(f"CVE: {', '.join(details['cve_ids'])}")
    click.echo(f"Tags: {', '.join(details['tags'])}")
    click.echo(f"Created: {details['created_at']}")
    click.echo(f"Updated: {details['updated_at']}")
    click.echo(f"Version: {details['version']}")
    click.echo("\nCode Snippets:")
    for name, code in details["code_snippets"].items():
        click.echo(f"  {name}:")
        click.echo(f"  {'=' * len(name)}")
        click.echo(f"   {truncate_string(code)}")
    return 0


@cli.command()
@click.option("--id", "-i", required=True, help="Blueprint ID")
@coro
@click.pass_context
async def regenerate(ctx, id):
    """Regenerate code snippets for a blueprint."""
    system = get_system(ctx)

    result = await system.regenerate_code(id)
    if "error" in result:
        click.echo(f"Error: {result['error']}")
        return 1
    click.echo(f"Successfully regenerated code for blueprint: {result['name']}")
    click.echo(f"Code snippets: {', '.join(result['code_snippets'])}")
    return 0


@cli.command()
@coro
@click.pass_context
async def stats(ctx):
    """Show blueprint statistics and counts."""
    system = get_system(ctx)

    stats = system.blueprint_service.count_blueprints()
    click.echo(f"Total blueprints: {stats['total']}")
    click.echo("\nBlueprints by package:")
    for package, count in stats["by_package"].items():
        click.echo(f"  {package}: {count}")
    click.echo("\nBlueprints by CVE:")
    for cve, count in stats["by_cve"].items():
        click.echo(f"  {cve}: {count}")
    click.echo("\nBlueprints by tag:")
    for tag, count in stats["by_tag"].items():
        click.echo(f"  {tag}: {count}")
    return 0


@cli.command()
@click.option("--id", "-i", required=True, help="Blueprint ID")
@click.option("--auto-run", is_flag=True, help="Automatically run container after building")
@click.option("--ports", default="8080-8090", help="Port range for container allocation")
@click.option("--validate", is_flag=True, help="Automatically validate exploits after building containers")
@click.option("--background", is_flag=True, help="Run containers in background")
@coro
@click.pass_context
async def container(ctx, id, auto_run, ports, validate, background):
    """Build and optionally run a container for a specific blueprint."""
    return await _container_command(ctx, id, auto_run, ports, validate, background)


async def _container_command(ctx, id, auto_run, ports, validate, _background):
    """Execute the container command."""
    system = get_system(ctx)

    global running_containers
    running_containers = []

    try:
        click.echo(f"Building container for blueprint {id}...")
        result = await system.build_container(id)

        if result["status"] == "success":
            click.echo(f"\n✓ Container built successfully: {result['container_name']}")
            click.echo(f"Container directory: {result['container_dir']}")

            if auto_run:
                from utils.container.container_utils import PortAllocator

                port_allocator = PortAllocator(ports)
                allocated_port = port_allocator.allocate_port()

                if allocated_port:
                    port_mapping = [f"{allocated_port}:8080"]
                    run_result = await system.run_container(result["container_name"], port_mapping, id)

                    if run_result["status"] == "success":
                        click.echo(f"Container running on port {allocated_port}")
                        click.echo(f"Access: http://localhost:{allocated_port}")
                        click.echo(f"Container ID: {run_result['container_id']}")

                        container_info = {
                            "name": result["container_name"],
                            "id": run_result["container_id"],
                            "port": allocated_port,
                            "stop_command": run_result["stop_command"],
                        }
                        running_containers.append(container_info)

                        if validate:
                            # Run exploit validation automatically
                            click.echo(f"\nRunning exploit validation for blueprint {id}...")
                            validation_result = await system.validate_vulnerability_demo(id)

                            if validation_result.success and validation_result.vulnerability_demonstrated:
                                click.echo("  ✅ Vulnerability successfully validated")
                                click.echo(f"  📊 Execution time: {validation_result.execution_time:.1f}s")
                                if validation_result.exploitation_indicators:
                                    click.echo(
                                        f"Indicators found: {len(validation_result.exploitation_indicators)}"
                                    )
                                    for indicator in validation_result.exploitation_indicators[:3]:
                                        click.echo(f"    - {indicator}")
                                click.echo("\nMonitoring data saved to data/validateing/")
                            else:
                                click.echo(
                                    f"Validation failed: {validation_result.error_message or 'Unknown error'}"
                                )
                                return 1
                    else:
                        click.echo(f"✗ Failed to run container: {run_result.get('error', 'Unknown error')}")
                        return 1
                else:
                    click.echo("No available ports for container execution")
                    return 1
            else:
                click.echo("\nTo run the container:")
                click.echo(f"  podman run --rm -p 8080:8080 {result['container_name']}")
        else:
            click.echo(f"\n✗ Container build failed: {result.get('error', 'Unknown error')}")
            if "error_output" in result:
                click.echo(f"\nError details: {result['error_output']}")
            return 1
        return 0

    except KeyboardInterrupt:
        await cleanup_containers(running_containers)
        click.echo("\nOperation cancelled by user.")
        return 130
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error executing container command: {e}", exc_info=True)
        click.echo(f"Error: {e}")
        return 1


@cli.command()
@click.option(
    "--packages",
    "-p",
    multiple=True,
    default=["org.yaml:snakeyaml", "net.sf.ehcache:ehcache", "com.google.guava:guava"],
    help="Packages to process with guidance",
)
@click.option("--limit", "-l", type=int, default=2, help="Limit of vulnerabilities per package")
@click.option("--auto-run", is_flag=True, help="Automatically run containers after building")
@click.option("--ports", default="8080-8090", help="Port range for container allocation")
@click.option("--validate", is_flag=True, help="Automatically validate exploits after building containers")
@click.option("--background", is_flag=True, help="Run containers in background")
@click.option("--additional-deps", multiple=True, help="Additional Maven dependencies")
@click.option(
    "--framework-type",
    type=click.Choice(["spring-boot", "struts", "jenkins", "standalone"]),
    help="Force specific framework type",
)
@click.option("--cve-ids", "-cv", multiple=True, help="Specific CVE IDs for packages")
@coro
@click.pass_context
async def workflow(
    ctx, packages, limit, auto_run, ports, validate, background, additional_deps, framework_type, cve_ids
):
    """Execute enhanced workflow with validateing and validation."""
    return await _workflow_command(
        ctx, packages, limit, auto_run, ports, validate, background, additional_deps, framework_type, cve_ids
    )


async def _workflow_command(
    ctx, packages, limit, auto_run, ports, validate, background, additional_deps, framework_type, cve_ids
):
    """Execute the workflow command."""
    system = get_system(ctx)

    # Parse dependencies and CVE IDs
    additional_dependencies = parse_additional_dependencies(additional_deps)
    parsed_cve_ids = parse_cve_ids(cve_ids) if cve_ids else None

    global running_containers
    running_containers = []

    try:
        workflow_service = WorkflowService(system)
        workflow_results = await workflow_service.enhanced_process_workflow(
            packages=packages,
            limit=limit,
            cve_ids=parsed_cve_ids,
            auto_run=auto_run,
            port_range=ports,
            validate=validate,
            background=background,
            additional_dependencies=additional_dependencies,
            framework_type=framework_type,
        )

        log_workflow_summary(workflow_results)

        # Workflow service now handles validation internally when --validate flag is used

        return 0 if not workflow_results["errors"] else 1

    except KeyboardInterrupt:
        await cleanup_containers(running_containers)
        click.echo("\nOperation cancelled by user.")
        return 130
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error executing workflow command: {e}", exc_info=True)
        click.echo(f"Error: {e}")
        return 1


# Utility commands
@cli.command()
def health_check():
    """Check system health and status."""
    return execute_health_commands(type("Args", (), {"command": "health-check"})())


@cli.command()
def validate_templates():
    """Validate vulnerability templates for syntax and completeness."""
    return execute_template_validation()


@cli.command()
@click.option("--id", "-i", help="Blueprint ID to validate exploit for")
@coro
@click.pass_context
async def validate_exploit(ctx, id):
    """Validate exploit for a specific blueprint."""
    return await _validate_exploit_command(ctx, id)


async def _validate_exploit_command(ctx, id):
    """Execute the validate-exploit command."""
    if not id:
        click.echo("Error: --id required for validate-exploit command")
        return 1

    system = get_system(ctx)

    try:
        click.echo(f"Validating exploit for blueprint {id}...")
        result = await system.validate_vulnerability_demo(id)

        click.echo("\nValidation Results:")
        click.echo(f"Success: {result.success}")
        click.echo(f"Vulnerability Demonstrated: {result.vulnerability_demonstrated}")
        click.echo(f"Execution Time: {result.execution_time:.2f} seconds")

        if result.exploitation_indicators:
            click.echo("\nExploitation Indicators:")
            for indicator in result.exploitation_indicators:
                click.echo(f"  - {indicator}")

        if result.error_message:
            click.echo(f"\nError: {result.error_message}")

        click.echo("\nPersistent logs and reports have been saved to data/validateing/")
        return 0

    except Exception as e:
        click.echo(f"Error validating exploit: {e}")
        return 1


@cli.command()
@coro
async def stop_all():
    """Stop all running containers."""
    return await execute_stop_commands(type("Args", (), {"command": "stop-all"})())


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user.")
        sys.exit(130)
