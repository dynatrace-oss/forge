"""
Dependency Management Services

Services for handling Maven dependencies, version resolution, and package management.
"""

from .maven_version_resolver import MavenVersionResolver, VersionInfo

__all__ = ['MavenVersionResolver', 'VersionInfo']
