"""Plugin system and lifecycle hook manager for vShield."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


class PluginManager:
    """Manages lifecycle hooks for extending vShield without breaking core workflows."""

    def __init__(self):
        self._hooks: Dict[str, List[Callable[..., Any]]] = {
            "on_scan_start": [],
            "on_target_discovered": [],
            "on_evidence_collected": [],
            "on_finding": [],
            "on_scan_complete": [],
        }

    def register_hook(self, hook_name: str, handler: Callable[..., Any]) -> None:
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []
        self._hooks[hook_name].append(handler)

    def trigger(self, hook_name: str, *args: Any, **kwargs: Any) -> None:
        if hook_name not in self._hooks:
            return
        for handler in self._hooks[hook_name]:
            try:
                handler(*args, **kwargs)
            except Exception as e:
                logger.warning("Plugin hook %s failed: %s", hook_name, e)


# Global singleton instance
default_plugin_manager = PluginManager()
