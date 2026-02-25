# Copyright (c) 2025 Dynatrace LLC. All rights reserved.
#
# This software and associated documentation files (the "Software") are being
# made available by Dynatrace LLC for the sole purpose of illustrating the
# implementation of certain algorithms which are published. Permission is
# hereby granted, free of charge, to any person obtaining a copy of the
# Software, to view and use the Software for internal, non-production,
# non-commercial purposes only. Without limiting the foregoing, the Software
# may not (i) be used to process live data or train, fine-tune, enrich or
# improve any machine learning or foundation model or other artificial
# intelligence model or system or (ii) distributed, sublicensed, modified, used
# to provide a service, or sold either alone or as part of or in combination
# with any other software. The Software shall at all times be considered the
# proprietary property of Dynatrace LLC.
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging
from pathlib import Path
from typing import Any

import jinja2
import yaml

logger = logging.getLogger(__name__)

DEFAULT_PROMPTS_DIR = Path("data/prompts")


class PromptEngine:
    """Render prompt templates with Jinja2 inheritance, fragments, and StrictUndefined.

    Replaces the flat PromptStore with a v1-style engine supporting:
    - ``{% extends %}`` for template inheritance
    - ``{% block %}`` for overridable sections
    - ``{% include %}`` for reusable fragments
    - ``StrictUndefined``: missing variables raise errors immediately

    Template names use path-based keys relative to the prompts directory.
    For example: ``"build/template_system"``, ``"exploit/user"``,
    ``"fragments/container_guidelines"``.

    Directory layout::

        data/prompts/
        ├── base/          # Base templates with {% block %} definitions
        ├── fragments/     # Reusable {% include %} blocks
        ├── build/         # Build phase prompts
        ├── exploit/       # Exploit phase prompts
        ├── evolution/     # Template evolution prompts
        └── deploy/        # Deploy phase prompts

    YAML file format — single template::

        id: build_template_system
        template: |
          {% extends "base/base_system" %}
          {% block task %}Build a vulnerable app...{% endblock %}

    YAML file format — agent system prompt::

        system: |
          You are the Intel Agent in FORGE...
          {{ cve_id }}

    YAML file format — multi-fragment::

        fragments:
          security_constraints:
            template: |
              All work is performed in isolated sandbox containers...
          container_guidelines:
            template: |
              Dockerfile must EXPOSE 8080...
    """

    def __init__(self, prompts_dir: Path | None = None) -> None:
        self._dir = prompts_dir or DEFAULT_PROMPTS_DIR
        self._templates = _load_all(self._dir)
        self._env = jinja2.Environment(
            loader=jinja2.DictLoader(self._templates),
            undefined=jinja2.StrictUndefined,
            keep_trailing_newline=True,
        )

    def render(self, template_name: str, **context: Any) -> str:
        """Render a prompt template with full Jinja2 inheritance support.

        Args:
            template_name: Path-based key like ``"build/template_system"``
                or ``"exploit/user"``.
            **context: Jinja2 template variables.

        Returns:
            Rendered prompt string, stripped of leading/trailing whitespace.

        Raises:
            jinja2.TemplateNotFound: If *template_name* doesn't exist.
            jinja2.UndefinedError: If a required variable is missing.
        """
        template = self._env.get_template(template_name)
        return template.render(**context).strip()

    def raw(self, template_name: str) -> str:
        """Return the raw (unrendered) template string."""
        if template_name not in self._templates:
            msg = f"Template not found: {template_name}"
            raise jinja2.TemplateNotFound(template_name, message=msg)
        return self._templates[template_name]

    def list_prompts(self) -> list[str]:
        """List all available template names, sorted."""
        return sorted(self._templates)

    def has(self, template_name: str) -> bool:
        """Check whether a template exists."""
        return template_name in self._templates


def _load_all(prompts_dir: Path) -> dict[str, str]:
    """Walk the prompts directory and build a name-to-source mapping.

    Single-template YAML files (containing a ``template:`` key) are stored
    under their path-based key — e.g. ``base/base_system.yaml`` becomes
    ``"base/base_system"``.

    Multi-fragment YAML files (containing a ``fragments:`` key) store each
    fragment separately — e.g. a fragment named ``security_constraints``
    inside ``fragments/fragments.yaml`` becomes
    ``"fragments/security_constraints"``.
    """
    templates: dict[str, str] = {}

    for yaml_path in sorted(prompts_dir.rglob("*.yaml")):
        rel = yaml_path.relative_to(prompts_dir)
        data: Any = yaml.safe_load(yaml_path.read_text())

        if not isinstance(data, dict):
            logger.warning("Skipping non-dict YAML: %s", yaml_path)
            continue

        # Single template file (supports both 'template:' and 'system:' keys)
        if "template" in data:
            key = str(rel.with_suffix(""))
            templates[key] = str(data["template"])
            logger.debug("Loaded template: %s", key)
        elif "system" in data:
            key = str(rel.with_suffix(""))
            templates[key] = str(data["system"])
            logger.debug("Loaded system prompt: %s", key)

        # Multi-fragment file
        if "fragments" in data and isinstance(data["fragments"], dict):
            parent = str(rel.parent)
            for name, frag in data["fragments"].items():
                if isinstance(frag, dict) and "template" in frag:
                    key = f"{parent}/{name}" if parent != "." else name
                    templates[key] = str(frag["template"])
                    logger.debug("Loaded fragment: %s", key)

    return templates
