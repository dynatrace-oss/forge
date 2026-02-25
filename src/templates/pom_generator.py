import asyncio
import logging

from models.error_handling import TemplateError
from shared.types import FrameworkType
from utils.core import package_utils, pom_utils, version_utils
from utils.core.common import extract_package_parts
from utils.core.prompt_manager import prompt_manager

logger = logging.getLogger(__name__)


class PomGenerator:
    """
    Extracts POM-related methods from TemplateManager to keep concerns separated.
    Depends on TemplateManager for shared framework-detection helpers and on the
    supporting services that TemplateManager already owns.

    Args:
        template_manager: Parent TemplateManager instance (provides shared helpers,
            loader, renderer, framework_metadata_service, and llm_service).
    """

    def __init__(self, template_manager: object) -> None:
        self._tm = template_manager

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_pom_xml(
        self,
        blueprint: object,
        main_class_name: str,
        additional_dependencies: list[dict[str, object]] = None,
        framework_adaptation_dependencies: list[dict[str, object]] = None,
    ) -> str:
        """
        Generate a complete POM XML file for a blueprint.

        Args:
            blueprint: Blueprint with vulnerability information.
            main_class_name: Name of the main class.
            additional_dependencies: Additional dependencies to include.
            framework_adaptation_dependencies: Dependencies from framework adaptation
                (e.g., Struts plugins).

        Returns:
            Complete POM XML content as a string.

        Raises:
            TemplateError: If POM generation fails.
        """
        try:
            group_id, artifact_id = extract_package_parts(blueprint.package_name)
            logger.info(
                f"Extracted group_id={group_id}, artifact_id={artifact_id} "
                f"from {blueprint.package_name}"
            )

            # Ensure package version is set
            if not blueprint.package_version or blueprint.package_version.strip() == "":
                logger.error(
                    f"Package version not set for {blueprint.package_name}. "
                    "OSV version extraction failed."
                )
                suggested_version = self._determine_version_with_llm(blueprint)
                if suggested_version:
                    blueprint.package_version = suggested_version
                    logger.info(
                        f"LLM suggested version {suggested_version} "
                        f"for {blueprint.package_name}"
                    )
                else:
                    logger.error(
                        f"Failed to determine version for {blueprint.package_name}. "
                        "Cannot proceed with POM generation."
                    )
                    raise ValueError(
                        f"No valid version found for package {blueprint.package_name}. "
                        "Both OSV extraction and LLM determination failed."
                    )

            # Determine framework type
            framework_metadata = (blueprint.metadata or {}).get("framework_adaptation", {})
            if framework_metadata.get("selected_framework"):
                selected_framework = framework_metadata["selected_framework"]
                logger.info(f"Using framework from adaptation: {selected_framework}")
                framework_type_str = selected_framework
            else:
                vulnerability_data = {
                    "package_name": blueprint.package_name,
                    "cve_id": blueprint.cve_ids[0] if blueprint.cve_ids else "",
                    "description": blueprint.description,
                    "summary": "",
                }
                framework_type = self._tm._detect_framework_from_patterns(vulnerability_data)
                framework_type_str = framework_type.value
                logger.info(
                    f"Detected framework type from patterns: {framework_type_str} "
                    f"for {blueprint.package_name}"
                )

            # Extract protocol_type from classification metadata
            protocol_type = (blueprint.metadata or {}).get("classification", {}).get(
                "protocol_type"
            )
            if protocol_type:
                logger.info(f"Protocol type detected: {protocol_type}")

            pom_template = self.get_pom_template(
                blueprint.package_name,
                framework_type=framework_type_str,
                protocol_type=protocol_type,
            )
            logger.debug(f"POM template content length: {len(pom_template)}")

            repositories = self.get_repository_templates(blueprint.package_name)
            logger.debug(f"Repository template content length: {len(repositories)}")

            # Resolve FrameworkType enum
            try:
                framework_type_enum = FrameworkType(framework_type_str)
            except ValueError:
                framework_type_enum = (
                    self._tm._map_framework_name_to_type(framework_type_str)
                    or FrameworkType.SPRING_BOOT
                )
                logger.warning(
                    f"Could not convert {framework_type_str} to FrameworkType, "
                    f"using {framework_type_enum.value}"
                )

            all_dependencies = self._get_all_dependencies(
                blueprint,
                additional_dependencies,
                framework_type_enum,
                framework_adaptation_dependencies,
            )
            dependencies_xml = self._tm.renderer.format_dependencies(all_dependencies)
            logger.debug(f"Dependencies XML length: {len(dependencies_xml)}")

            is_spring_core = package_utils.is_spring_framework_core_package(
                blueprint.package_name
            )
            spring_boot_version, java_version = version_utils.determine_spring_boot_version(
                blueprint.package_version,
                blueprint.package_name,
                is_spring_core=is_spring_core,
            )
            logger.info(
                f"Selected versions: Spring Boot {spring_boot_version} + "
                f"Java {java_version} for {blueprint.package_name} v{blueprint.package_version}"
            )

            is_servlet_container = package_utils.is_servlet_container_package(
                blueprint.package_name
            )
            if is_servlet_container:
                servlet_container_type = package_utils.detect_servlet_container_type(
                    blueprint.package_name
                )
                logger.info(
                    f"Testing servlet container: {servlet_container_type} "
                    "(package is the container itself)"
                )
            else:
                servlet_container_type = "tomcat"
                logger.debug(
                    "Using default servlet container: tomcat "
                    "(package is not a container)"
                )

            try:
                version_utils.validate_spring_compatibility(
                    blueprint.package_name,
                    blueprint.package_version,
                    spring_boot_version,
                    java_version,
                )
            except ValueError as e:
                raise TemplateError(
                    message=f"Version compatibility check failed for {blueprint.package_name}",
                    cause=e,
                    remedy=(
                        "Check the _determine_spring_boot_version() logic to ensure "
                        "correct version selection"
                    ),
                )

            project_name = artifact_id.replace("-", " ").title() + " Web Demo"

            context = {
                "group_id": group_id,
                "artifact_id": artifact_id,
                "package_version": blueprint.package_version,
                "package_name": blueprint.package_name,
                "main_class": main_class_name,
                "repositories": repositories,
                "dependencies": dependencies_xml,
                "spring_boot_version": spring_boot_version,
                "java_version": java_version,
                "servlet_container": servlet_container_type,
                "project.version": "1.0-SNAPSHOT",
                "project.name": project_name,
                "project.build.sourceEncoding": "UTF-8",
                "spring-boot.version": spring_boot_version,
                "java.version": java_version,
                "servlet.api.version": "4.0.1",
                "jsp.api.version": "2.3.3",
                "jstl.version": "1.2",
                "tomcat.version": "9.0.80",
                "maven.compiler.version": "3.11.0",
                "maven.compiler.source": java_version,
                "maven.compiler.target": java_version,
                "maven.war.version": "3.4.0",
                "maven.surefire.version": "3.0.0",
            }
            logger.info(f"Template context keys: {list(context.keys())}")
            logger.info(
                f"Using package version: {blueprint.package_version} "
                f"for {blueprint.package_name}"
            )

            rendered_pom = self._tm.renderer.render_template(pom_template, context)
            logger.debug(f"Rendered POM XML length: {len(rendered_pom)}")

            for key in context.keys():
                placeholder = f"${{{key}}}"
                if placeholder in rendered_pom:
                    logger.warning(f"Unreplaced variable in POM XML: {placeholder}")

            rendered_pom = pom_utils.ensure_valid_pom_xml(rendered_pom)
            return rendered_pom

        except Exception as e:
            logger.error(f"Error generating POM XML: {str(e)}", exc_info=True)
            raise TemplateError(
                message=f"Error generating POM XML for {blueprint.package_name}",
                cause=e,
                remedy="Check the template format and blueprint information",
            )

    def get_pom_template(
        self,
        package_name: str,
        framework_type: str = None,
        protocol_type: str = None,
    ) -> str:
        """
        Get POM template based on framework type and package requirements.

        Uses framework_metadata_service for template selection.

        Args:
            package_name: Name of the vulnerable package.
            framework_type: Optional framework type hint (e.g., 'standalone_jar',
                'spring_boot', 'struts').
            protocol_type: Optional protocol type for protocol servers
                (e.g., 'HTTP/2', 'WebSocket').

        Returns:
            POM template content as string.

        Raises:
            FileNotFoundError: If no suitable template is found.
        """
        template_name = None

        if framework_type:
            framework_type_normalized = framework_type.lower().replace("-", "_")

            template_name = self._tm.framework_metadata_service.get_template_for_package(
                framework_type=framework_type_normalized,
                package_name=package_name,
                protocol_type=protocol_type,
            )

            if not template_name:
                default_templates = {
                    "spring_boot": "spring_boot_web.xml",
                    "apache_struts": "servlet_container.xml",
                    "standalone_jar": "standalone_jar.xml",
                    "micronaut": "microservice_native.xml",
                    "quarkus": "microservice_native.xml",
                    "protocol_server": "standalone_jar.xml",
                    "kafka_client": "kafka_client.xml",
                }
                if framework_type_normalized in default_templates:
                    template_name = default_templates[framework_type_normalized]
                    logger.info(
                        f"Using default template for adapted framework "
                        f"'{framework_type_normalized}': {template_name} "
                        f"(no specific pattern matched for {package_name})"
                    )

        if not template_name and not framework_type:
            for fw_type in [
                "spring_boot",
                "apache_struts",
                "micronaut",
                "quarkus",
                "standalone_jar",
                "protocol_server",
            ]:
                template_name = self._tm.framework_metadata_service.get_template_for_package(
                    framework_type=fw_type,
                    package_name=package_name,
                    protocol_type=protocol_type,
                )
                if template_name:
                    logger.info(
                        f"Template selected by pattern matching: {template_name} "
                        f"(framework: {fw_type})"
                    )
                    break

        if template_name:
            template_path = self._tm.core_templates_dir / template_name
            logger.info(f"Using template: {template_name} for package: {package_name}")
            if template_path.exists():
                return self._tm.loader.load_template_content(template_path, required=True)
            else:
                logger.warning(
                    f"Template {template_name} not found at {template_path}, "
                    "trying fallback"
                )

        fallback_template = "standalone_jar.xml"
        fallback_path = self._tm.core_templates_dir / fallback_template
        if fallback_path.exists():
            logger.info(
                f"Using fallback template: {fallback_template} "
                f"for package: {package_name}"
            )
            return self._tm.loader.load_template_content(fallback_path, required=True)

        universal_fallback = self._tm.templates_dir / "universal_web.xml"
        if universal_fallback.exists():
            logger.warning(
                f"Using universal fallback template for package: {package_name}"
            )
            return self._tm.loader.load_template_content(universal_fallback, required=True)

        raise FileNotFoundError(
            f"No POM template found for package '{package_name}' with framework type "
            f"'{framework_type}'. Checked: metadata-driven selection, pattern matching, "
            "and fallback templates.\n"
            "Please ensure templates exist in templates/core/ directory."
        )

    def get_repository_templates(self, package_name: str) -> str:
        """
        Generate repository configurations dynamically based on the package name.

        Loads repository templates from files instead of hardcoding XML.

        Args:
            package_name: Package name.

        Returns:
            XML content for Maven repositories.
        """
        repositories = []
        repos_dir = self._tm.templates_dir / "maven" / "repositories"

        maven_central_path = repos_dir / "maven_central.xml"
        if maven_central_path.exists():
            repositories.append(maven_central_path.read_text().strip())
        else:
            logger.warning(f"Maven Central template not found: {maven_central_path}")

        package_lower = package_name.lower()

        if "snakeyaml" in package_lower or "javax.script" in package_lower:
            xwiki_path = repos_dir / "xwiki.xml"
            if xwiki_path.exists():
                repositories.append(xwiki_path.read_text().strip())
            else:
                logger.warning(f"XWiki repository template not found: {xwiki_path}")

        if "jboss" in package_lower or "hibernate" in package_lower:
            jboss_path = repos_dir / "jboss.xml"
            if jboss_path.exists():
                repositories.append(jboss_path.read_text().strip())
            else:
                logger.warning(f"JBoss repository template not found: {jboss_path}")

        repositories_xml = f"""<repositories>
{chr(10).join(repositories)}
    </repositories>"""

        return repositories_xml

    def _get_all_dependencies(
        self,
        blueprint: object,
        additional_dependencies: list[dict[str, object]] = None,
        framework_type: object = None,
        framework_adaptation_dependencies: list[dict[str, object]] = None,
    ) -> list[dict[str, object]]:
        """
        Assemble all Maven dependencies for a blueprint.

        Args:
            blueprint: Blueprint with vulnerability information.
            additional_dependencies: Explicitly provided extra dependencies.
            framework_type: FrameworkType enum value for conditional logic.
            framework_adaptation_dependencies: Dependencies from framework adaptation
                (e.g., Struts plugins); versions are resolved and validated against
                Maven Central.

        Returns:
            List of dependency dictionaries with keys 'group_id', 'artifact_id',
            'version'.
        """
        group_id, artifact_id = extract_package_parts(blueprint.package_name)

        dependencies: list[dict[str, object]] = []

        if package_utils.is_spring_framework_core_package(blueprint.package_name):
            logger.info(
                f"SKIPPING explicit dependency for Spring Framework CORE package: "
                f"{blueprint.package_name}"
            )
            logger.info(
                "This package will be managed by Spring Boot with version override "
                "via dependencyManagement"
            )
            logger.info(f"Target version: {blueprint.package_version}")
        elif package_utils.is_servlet_container_package(blueprint.package_name):
            logger.info(
                f"SKIPPING explicit dependency for SERVLET CONTAINER package: "
                f"{blueprint.package_name}"
            )
            logger.info(
                "This package will be included by Spring Boot starter "
                "(spring-boot-starter-undertow/jetty/webflux)"
            )
            logger.info(f"Target version: {blueprint.package_version}")
        else:
            logger.info(
                f"Adding main vulnerability dependency: "
                f"{blueprint.package_name} @ {blueprint.package_version}"
            )
            dependencies.append(
                {
                    "group_id": group_id,
                    "artifact_id": artifact_id,
                    "version": blueprint.package_version,
                }
            )

        if framework_type and framework_type not in [FrameworkType.SPRING_BOOT]:
            logger.info(
                f"Adding slf4j-simple for non-Spring Boot framework: {framework_type}"
            )
            dependencies.append(
                {
                    "group_id": "org.slf4j",
                    "artifact_id": "slf4j-simple",
                    "version": "1.7.32",
                }
            )
            dependencies.append(
                {
                    "group_id": "org.slf4j",
                    "artifact_id": "slf4j-api",
                    "version": "1.7.32",
                }
            )
        else:
            logger.info("Skipping slf4j-simple for Spring Boot (uses logback by default)")

        if additional_dependencies:
            dependencies.extend(additional_dependencies)

        if framework_adaptation_dependencies:
            logger.info(
                f"Merging {len(framework_adaptation_dependencies)} framework adaptation "
                "dependencies into POM"
            )

            from services.dependency.maven_version_resolver import MavenVersionResolver

            version_resolver = MavenVersionResolver()
            existing_keys = {
                f"{d['group_id']}:{d['artifact_id']}" for d in dependencies
            }

            for dep in framework_adaptation_dependencies:
                if not all(k in dep for k in ["group_id", "artifact_id"]):
                    logger.warning(
                        f"Skipping invalid framework dependency "
                        f"(missing group_id or artifact_id): {dep}"
                    )
                    continue

                dep_key = f"{dep.get('group_id')}:{dep.get('artifact_id')}"

                if dep_key in existing_keys:
                    logger.warning(f"Skipping duplicate dependency: {dep_key}")
                    continue

                if "version" not in dep or not dep["version"] or not dep["version"].strip():
                    try:
                        version_info = version_resolver.resolve_version(
                            group_id=dep["group_id"],
                            artifact_id=dep["artifact_id"],
                            target_version=blueprint.package_version,
                            strategy="match_major",
                        )
                        dep["version"] = version_info.version
                        logger.info(
                            f"Resolved version for {dep_key} → {version_info.version} "
                            f"(via {version_info.resolved_via})"
                        )
                    except ValueError as e:
                        logger.warning(f"Skipping incompatible dependency {dep_key}: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Failed to resolve version for {dep_key}: {e}")
                        continue
                else:
                    logger.debug(
                        f"Verifying LLM-provided version: {dep_key}:{dep['version']}"
                    )
                    if not version_resolver.version_exists(
                        dep["group_id"], dep["artifact_id"], dep["version"]
                    ):
                        logger.warning(
                            f"LLM-provided version {dep['version']} not found in Maven "
                            f"Central for {dep_key}, resolving alternative..."
                        )
                        try:
                            version_info = version_resolver.resolve_version(
                                dep["group_id"],
                                dep["artifact_id"],
                                target_version=blueprint.package_version,
                                strategy="match_major",
                            )
                            old_version = dep["version"]
                            dep["version"] = version_info.version
                            logger.info(
                                f"Replaced invalid version {old_version} → "
                                f"{version_info.version} for {dep_key}"
                            )
                        except ValueError as e:
                            logger.warning(
                                f"Skipping incompatible dependency {dep_key}: {e}"
                            )
                            continue
                        except Exception as e:
                            logger.error(
                                f"Could not resolve alternative version for {dep_key}: {e}"
                            )
                            continue

                dependencies.append(dep)
                logger.info(
                    f"Added framework dependency: {dep_key}:{dep.get('version')}"
                )
                existing_keys.add(dep_key)

        return dependencies

    def _determine_version_with_llm(self, blueprint: object) -> str | None:
        """
        Use LLM to determine an appropriate version when OSV extraction fails.

        Args:
            blueprint: Blueprint object with package information.

        Returns:
            Suggested version string or None if determination fails.
        """
        try:
            if not self._tm.llm_service:
                logger.warning("No LLM service available for version determination")
                return None

            osv_metadata = ""
            if hasattr(blueprint, "metadata") and (blueprint.metadata or {}).get("osv_data"):
                osv_data = (blueprint.metadata or {})["osv_data"]
                if "affected" in osv_data:
                    osv_metadata = f"OSV Affected Packages: {osv_data['affected'][:2]}"

            rendered_prompt = prompt_manager.format_prompt(
                "version_determination",
                package_name=blueprint.package_name,
                cve_ids=", ".join(blueprint.cve_ids) if blueprint.cve_ids else "None",
                description=blueprint.description or "No description available",
                osv_metadata=osv_metadata or "No OSV metadata available",
            )

            try:
                try:
                    _ = asyncio.get_running_loop()
                    import concurrent.futures

                    def run_llm_task():
                        new_loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(new_loop)
                        try:
                            return new_loop.run_until_complete(
                                asyncio.wait_for(
                                    self._tm.llm_service.generate(rendered_prompt),
                                    timeout=15.0,
                                )
                            )
                        finally:
                            new_loop.close()

                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(run_llm_task)
                        result = future.result(timeout=18.0)

                except RuntimeError:
                    result = asyncio.run(
                        asyncio.wait_for(
                            self._tm.llm_service.generate(rendered_prompt), timeout=15.0
                        )
                    )

                if result and isinstance(result, str):
                    suggested_version = version_utils.extract_and_validate_version(
                        result.strip()
                    )
                    if suggested_version:
                        logger.info(
                            f"LLM successfully determined version {suggested_version} "
                            f"for {blueprint.package_name}"
                        )
                        return suggested_version
                    else:
                        logger.warning(
                            f"LLM response '{result.strip()}' did not contain a valid "
                            f"version for {blueprint.package_name}"
                        )
                else:
                    logger.warning(
                        "LLM returned empty or invalid response for version "
                        f"determination of {blueprint.package_name}"
                    )

            except (asyncio.TimeoutError, Exception) as e:
                logger.error(
                    f"LLM version determination failed for {blueprint.package_name}: {e}"
                )

        except Exception as e:
            logger.error(
                f"Error in LLM version determination for {blueprint.package_name}: {e}",
                exc_info=True,
            )

        return None
