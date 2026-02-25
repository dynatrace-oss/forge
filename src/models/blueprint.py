import uuid
from datetime import datetime


class Blueprint:
    """
    Blueprint model representing a vulnerable application design.
    Contains metadata, version information, and package vulnerabilities.
    """

    def __init__(
        self,
        name: str,
        description: str,
        package_name: str,
        package_version: str,
        cve_ids: list[str],
        author: str = "System",
        created_at: datetime | None = None,
        blueprint_id: str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, any] | None = None,
        version: int = 1,
        **kwargs,
    ):
        """
        Initialize a new Blueprint instance.

        Args:
            name: Name of the blueprint
            description: Description of the blueprint
            package_name: Name of the vulnerable package
            package_version: Version of the vulnerable package
            cve_ids: list of CVE IDs associated with this blueprint
            author: Author of the blueprint
            created_at: Creation timestamp
            blueprint_id: Unique identifier for the blueprint
            tags: list of tags for categorization
            metadata: Additional metadata as key-value pairs
            version: Version of the blueprints
            **kwargs: Additional attributes including:
                - code_snippets: dictionary of code snippets for vulnerability implementation
                - endpoint_metadata: LLM-provided endpoint information (path, method, consumes)
                - cvss_score: CVSS score (0.0-10.0)
                - severity_level: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
                - attack_vector: Attack vector (NETWORK, ADJACENT, LOCAL, PHYSICAL)
                - attack_complexity: Attack complexity (LOW, HIGH)
        """
        self.blueprint_id = blueprint_id or str(uuid.uuid4())
        self.name = name
        self.description = description
        self.package_name = package_name
        self.package_version = package_version
        self.cve_ids = cve_ids
        self.author = author
        self.created_at = created_at or datetime.now()
        self.tags = tags or []
        self.metadata = metadata or {}
        self.version = version

        # Extract implementation artifacts from kwargs
        self.code_snippets = kwargs.get("code_snippets") or {}
        self.endpoint_metadata = kwargs.get("endpoint_metadata") or []

        # Extract security attributes from kwargs
        self.cvss_score = kwargs.get("cvss_score")
        self.severity_level = kwargs.get("severity_level")
        self.attack_vector = kwargs.get("attack_vector")
        self.attack_complexity = kwargs.get("attack_complexity")
        self.updated_at = self.created_at

    def get_framework_type(self) -> str:
        """
        Get framework type from metadata.

        Returns:
            Framework type string
        """
        framework_info = self.metadata.get("framework_info", {})

        # Check for forced type first
        if "forced_type" in framework_info:
            return framework_info["forced_type"]

        # Check for detected type
        if "detected_type" in framework_info:
            return framework_info["detected_type"]

        # Infer from enhanced metadata
        enhanced_meta = self.metadata.get("enhanced_metadata", {})
        framework_type = enhanced_meta.get("framework_type", "unknown")

        if framework_type != "unknown":
            return framework_type

        # Default inference
        if "spring" in self.package_name.lower() or "spring" in self.description.lower():
            return "spring-boot"
        elif "struts" in self.package_name.lower() or "struts" in self.description.lower():
            return "struts"
        elif "jenkins" in self.package_name.lower():
            return "jenkins"
        else:
            return "standalone"

    def set_framework_type(self, framework_type: str) -> None:
        """
        Set framework type in metadata.

        Args:
            framework_type: Framework type to set
        """
        if "framework_info" not in self.metadata:
            self.metadata["framework_info"] = {}

        self.metadata["framework_info"]["detected_type"] = framework_type
        self.updated_at = datetime.now()

    def update(self, **kwargs) -> None:
        """
        Update blueprint attributes.

        Args:
            **kwargs: Attributes to update
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        self.version += 1
        self.updated_at = datetime.now()

    def add_code_snippet(self, name: str, code: str) -> None:
        """
        Add a code snippet to the blueprint.

        Args:
            name: Name/identifier for the code snippet
            code: The code snippet content
        """
        self.code_snippets[name] = code
        self.updated_at = datetime.now()

    def add_tag(self, tag: str) -> None:
        """
        Add a tag to the blueprint.

        Args:
            tag: Tag to add
        """
        if tag not in self.tags:
            self.tags.append(tag)
            self.updated_at = datetime.now()

    def remove_tag(self, tag: str) -> None:
        """
        Remove a tag from the blueprint.

        Args:
            tag: Tag to remove
        """
        if tag in self.tags:
            self.tags.remove(tag)
            self.updated_at = datetime.now()

    def add_metadata(self, key: str, value: any) -> None:
        """
        Add metadata to the blueprint.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value
        self.updated_at = datetime.now()

    def get_severity_color(self) -> str:
        """
        Get color code for severity level visualization.

        Returns:
            Color code string for severity level
        """
        severity_colors = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "orange", "CRITICAL": "red"}
        return severity_colors.get(self.severity_level, "gray")

    def is_high_severity(self) -> bool:
        """
        Check if vulnerability is high severity (HIGH or CRITICAL).

        Returns:
            True if vulnerability is high severity
        """
        return self.severity_level in ["HIGH", "CRITICAL"]

    def get_cvss_category(self) -> str:
        """
        Get CVSS score category based on standard ranges.

        Returns:
            CVSS category string
        """
        if self.cvss_score is None:
            return "Unknown"
        elif abs(self.cvss_score - 0.0) < 1e-9:
            return "None"
        elif self.cvss_score <= 3.9:
            return "Low"
        elif self.cvss_score <= 6.9:
            return "Medium"
        elif self.cvss_score <= 8.9:
            return "High"
        else:
            return "Critical"

    def update_cve_data(
        self,
        cvss_score: float = None,
        severity_level: str = None,
        attack_vector: str = None,
        attack_complexity: str = None,
    ) -> None:
        """
        Update CVE-related data fields.

        Args:
            cvss_score: CVSS score (0.0-10.0)
            severity_level: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            attack_vector: Attack vector (NETWORK, ADJACENT, LOCAL, PHYSICAL)
            attack_complexity: Attack complexity (LOW, HIGH)
        """
        if cvss_score is not None:
            self.cvss_score = cvss_score
        if severity_level is not None:
            self.severity_level = severity_level.upper()
        if attack_vector is not None:
            self.attack_vector = attack_vector.upper()
        if attack_complexity is not None:
            self.attack_complexity = attack_complexity.upper()

        self.updated_at = datetime.now()

    def to_dict(self) -> dict[str, any]:
        """
        Convert blueprint to dictionary representation.

        Returns:
            dictionary representation of the blueprint
        """
        return {
            "blueprint_id": self.blueprint_id,
            "name": self.name,
            "description": self.description,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "cve_ids": self.cve_ids,
            "author": self.author,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": self.tags,
            "metadata": self.metadata,
            "code_snippets": self.code_snippets,
            "endpoint_metadata": self.endpoint_metadata,
            "version": self.version,
            "cvss_score": self.cvss_score,
            "severity_level": self.severity_level,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, any]) -> "Blueprint":
        """
        Create a Blueprint instance from a dictionary.

        Args:
            data: dictionary representation of a blueprint

        Returns:
            Blueprint instance
        """
        # Convert ISO format strings back to datetime objects
        created_at = datetime.fromisoformat(data.pop("created_at"))
        data.pop("updated_at", None)  # Remove updated_at as it will be set by constructor

        if "metadata" in data and data["metadata"] is None:
            data.pop("metadata")

        return cls(created_at=created_at, **data)
