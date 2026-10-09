"""
==============================================================================
FILE: apps/api/app/attack_paths/service.py
ROLE / OWNERSHIP: Cybersecurity & Threat Modelers
OBJECTIVE: Orchestration service for attack path analysis, caching, and persistence.
==============================================================================
"""

import logging
from typing import List, Optional

from app.digital_twin.builder import get_digital_twin_builder
from app.db.repositories.attack_path_repository import get_attack_path_repository
from app.schemas.attack_path import AttackPathResponse, ReachabilityStatus
from app.attack_paths.engine import AttackPathEngine

logger = logging.getLogger("gasha.attack_paths.service")


class AttackPathService:
    def __init__(self):
        self.builder = get_digital_twin_builder()
        self.path_repo = get_attack_path_repository()
        self.engine = AttackPathEngine()

    def recalculate_attack_paths(self, environment_id: str) -> List[AttackPathResponse]:
        """
        Constructs current digital twin topology, computes attack paths,
        and updates persistent repository.
        """
        logger.info(f"Recalculating attack paths for environment: {environment_id}")
        graph = self.builder.build_graph_for_environment(environment_id=environment_id)
        paths = self.engine.find_attack_paths(graph=graph)

        self.path_repo.save_attack_paths(environment_id=environment_id, paths=paths)
        return paths

    def list_attack_paths(
        self,
        environment_id: str,
        is_active: Optional[bool] = None,
        reachability: Optional[ReachabilityStatus] = None
    ) -> List[AttackPathResponse]:
        paths = self.path_repo.list_attack_paths(
            environment_id=environment_id,
            is_active=is_active,
            reachability=reachability
        )
        if not paths and is_active is None and reachability is None:
            # If not yet calculated, calculate now
            return self.recalculate_attack_paths(environment_id=environment_id)
        return paths

    def get_attack_path(self, path_id: str, environment_id: str) -> Optional[AttackPathResponse]:
        return self.path_repo.get_attack_path(path_id=path_id, environment_id=environment_id)


_attack_path_service_instance: Optional[AttackPathService] = None

def get_attack_path_service() -> AttackPathService:
    global _attack_path_service_instance
    if _attack_path_service_instance is None:
        _attack_path_service_instance = AttackPathService()
    return _attack_path_service_instance
