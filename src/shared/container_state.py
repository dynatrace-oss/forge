import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class ContainerStateManager:
    """Centralized container state management."""
    
    def __init__(self):
        self._running_containers: List[Dict[str, Any]] = []
    
    def set_running_containers(self, containers: List[Dict[str, Any]]) -> None:
        """Set the current running containers list."""
        self._running_containers = containers
    
    def get_running_containers(self) -> Dict[str, Any]:
        """Get running containers in dict format."""
        try:
            if isinstance(self._running_containers, list):
                # Convert list to dict format
                result = {}
                for container in self._running_containers:
                    name = container.get('name', container.get('container_name', ''))
                    if name:
                        result[name] = container
                return result
            return self._running_containers if isinstance(self._running_containers, dict) else {}
        except Exception as e:
            logger.error(f"Error getting running containers: {e}")
            return {}
    
    def add_container(self, container: Dict[str, Any]) -> None:
        """Add a container to the running containers list."""
        if isinstance(self._running_containers, list):
            self._running_containers.append(container)
    
    def remove_container(self, container_name: str) -> None:
        """Remove a container from the running containers list."""
        if isinstance(self._running_containers, list):
            self._running_containers = [
                c for c in self._running_containers 
                if c.get('name', c.get('container_name', '')) != container_name
            ]


# Global instance
container_state_manager = ContainerStateManager()