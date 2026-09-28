"""
checker/engine/scan_depth.py

Defines scan depth configurations to restrict or expand the volume,
thoroughness, and duration of an authorization scan.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any


@dataclass
class ScanDepthConfig:
    """Controls the volume and thoroughness of a scan."""
    depth: str = "standard"  # 'quick', 'standard', 'deep'

    def __post_init__(self) -> None:
        if self.depth not in ("quick", "standard", "deep"):
            self.depth = "standard"

    @property
    def max_role_pairs(self) -> int:
        """Maximum number of cross-role permutations to evaluate."""
        return {"quick": 1, "standard": 4, "deep": 99}[self.depth]

    @property
    def max_ids_per_resource(self) -> int:
        """Maximum IDs tested per resource type for each role."""
        return {"quick": 1, "standard": 2, "deep": 99}[self.depth]

    @property
    def run_lifecycle(self) -> bool:
        """Whether to run autonomous entity discovery and canary creation."""
        return self.depth in ("standard", "deep")

    @property
    def run_mutation_verification(self) -> bool:
        """Whether to verify state mutations by re-reading objects."""
        return self.depth == "deep"

    @property
    def fuzz_variants(self) -> list[Any]:
        """Boundary and malformed ID values to test in ID manipulation."""
        variants = {
            "quick": [99999],
            "standard": [99999, -1],
            "deep": [99999, -1, "null"],
        }
        return variants[self.depth]

    @property
    def max_query_params(self) -> int:
        """Maximum user-id query parameters to probe."""
        return {"quick": 1, "standard": 2, "deep": 3}[self.depth]

    @property
    def build_full_acm(self) -> bool:
        """Whether to build full Access Control Matrix and detect anomalies."""
        return True

    @property
    def generate_poe(self) -> bool:
        """Always generate PoE reproduction scripts for vulnerabilities."""
        return True
