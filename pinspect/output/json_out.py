"""
SIEM/EDR structured JSON serialization.
"""

import json
from dataclasses import is_dataclass, asdict
from enum import Enum
from typing import Any, Dict, List, Union


class EDRJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for dataclasses, enums, sets, and custom types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, set):
            return sorted(list(obj))
        elif is_dataclass(obj):
            return asdict(obj)
        elif hasattr(obj, "__dict__"):
            return obj.__dict__
        return super().default(obj)


def to_json(data: Any, indent: int = 2) -> str:
    """Convert any pinspect data structure to SIEM/EDR structured JSON string."""
    return json.dumps(data, cls=EDRJSONEncoder, indent=indent, sort_keys=False)
