import logging
import os
from pathlib import Path

from utils.container.container_utils import check_disk_space

logger = logging.getLogger(__name__)


def run_pre_build_diagnostics(container_dir: str, container_name: str) -> None:
    """
    Run diagnostics before container build to identify potential issues early.

    Args:
        container_dir: Path to container directory
        container_name: Name of the container being built
    """
    logger.info(f"Running pre-build diagnostics for {container_name}")

    try:
        # Check Java files syntax if this is a Java project
        pom_path = os.path.join(container_dir, "pom.xml")
        if os.path.exists(pom_path):
            check_java_project_health(container_dir)

        # Check Containerfile/Dockerfile syntax
        check_containerfile_health(container_dir)

        # Check file permissions
        check_file_permissions(container_dir)

        # Check available disk space
        available_space = check_disk_space(container_dir)
        logger.info(f"Available disk space: {available_space / (1024*1024):.1f} MB")

        logger.info("Pre-build diagnostics completed")

    except Exception as e:
        logger.warning(f"Pre-build diagnostics failed: {e}")


def check_java_project_health(container_dir: str) -> None:
    """
    Validate Java project structure and syntax.

    Args:
        container_dir: Path to container directory
    """
    logger.info("Checking Java project health")

    java_files = list(Path(container_dir).glob("**/*.java"))
    logger.info(f"   Found {len(java_files)} Java files")

    for java_file in java_files[:5]:
        try:
            with open(java_file, 'r', encoding='utf-8') as f:
                content = f.read()

            if not content.strip():
                logger.warning(f"Empty Java file: {java_file}")
            elif content.count('{') != content.count('}'):
                logger.warning(f"Mismatched braces in: {java_file}")
            elif "package " in content and not content.startswith("package "):
                lines = [line.strip() for line in content.split('\n') if line.strip()]
                non_comment_lines = [line for line in lines if not line.startswith('//') and not line.startswith('/*')]
                if non_comment_lines and not non_comment_lines[0].startswith('package '):
                    logger.warning(f"Package declaration not at beginning: {java_file}")

        except Exception as e:
            logger.warning(f"Could not check Java file {java_file}: {e}")

    pom_path = os.path.join(container_dir, "pom.xml")
    if os.path.exists(pom_path):
        try:
            with open(pom_path, 'r', encoding='utf-8') as f:
                pom_content = f.read()

            if pom_content.count('<') != pom_content.count('>'):
                logger.warning("Malformed XML in pom.xml")
            elif '<project ' not in pom_content and '<project>' not in pom_content:
                logger.warning("Missing <project> root element in pom.xml")
            elif '<groupId>' not in pom_content or '<artifactId>' not in pom_content:
                logger.warning("Missing required Maven coordinates in pom.xml")
            else:
                logger.info("pom.xml appears valid")

        except Exception as e:
            logger.warning(f"Could not validate pom.xml: {e}")


def check_containerfile_health(container_dir: str) -> None:
    """
    Validate Containerfile/Dockerfile syntax.

    Args:
        container_dir: Path to container directory
    """
    logger.info("Checking Containerfile health")

    containerfile_path = os.path.join(container_dir, "Containerfile")
    dockerfile_path = os.path.join(container_dir, "Dockerfile")

    file_path = containerfile_path if os.path.exists(containerfile_path) else dockerfile_path

    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            lines = [line.strip() for line in content.split('\n') if line.strip()]

            if not any(line.startswith('FROM ') for line in lines):
                logger.warning("No FROM instruction found")
            elif not any('WORKDIR' in line for line in lines):
                logger.info("No WORKDIR instruction (may be intentional)")
            elif any('RUN mvn' in line for line in lines):
                logger.info("Maven build steps detected")
            else:
                logger.info("Containerfile appears valid")

        except Exception as e:
            logger.warning(f"Could not validate Containerfile: {e}")


def check_file_permissions(container_dir: str) -> None:
    """
    Verify file permissions in build directory.

    Args:
        container_dir: Path to container directory
    """
    logger.info("Checking file permissions")

    try:
        for root, dirs, files in os.walk(container_dir):
            for file in files[:10]:
                file_path = os.path.join(root, file)
                if not os.access(file_path, os.R_OK):
                    logger.warning(f"Cannot read file: {file_path}")
                elif file.endswith('.java') and not os.access(file_path, os.W_OK):
                    logger.warning(f"Cannot write to Java file: {file_path}")

        logger.info("File permissions appear OK")

    except Exception as e:
        logger.warning(f"Permission check failed: {e}")
