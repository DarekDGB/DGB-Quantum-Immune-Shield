from __future__ import annotations

from dataclasses import asdict

from shield_orchestrator.errors import TVAError

from .contracts.envelope import (
    OrchestratorV3Request,
    OrchestratorV3Response,
    TraceEntry,
)
from .contracts.reason_ids import ReasonId
from .contracts.version import CONTRACT_VERSION
from .context_hash import compute_context_hash


# Fixed pipeline order (contract-locked)
_COMPONENT_ORDER: tuple[tuple[str, str], ...] = (
    ("sentinel_ai", "sentinel_ai"),
    ("dqsn", "dqsn"),
    ("adn", "adn"),
    ("qwg", "qwg"),
    ("guardian_wallet", "guardian_wallet"),
)


def orchestrate(request: OrchestratorV3Request) -> OrchestratorV3Response:
    """
    Public Orchestrator v3 entrypoint.

    Phase 2 behavior:
    - strict request validation (version gate)
    - deterministic pipeline trace skeleton
    - fail-closed DENY (components not wired yet)

    Phase 3/4 will replace missing-component markers with real bridge calls.
    """
    try:
        _validate_request(request)

        trace: list[TraceEntry] = []

        # Stage 1: input validation
        trace.append(
            TraceEntry(
                stage="input_validation",
                component="orchestrator",
                status="OK",
            )
        )

        # Phase 2: components not wired yet → deterministic missing
        missing_reason = (ReasonId.COMPONENT_MISSING.value,)

        for stage, component in _COMPONENT_ORDER:
            trace.append(
                TraceEntry(
                    stage=stage,
                    component=component,
                    status="ERROR",
                    reason_ids=missing_reason,
                    notes="phase2_unwired",
                )
            )

        # Final synthesis (deny-by-default)
        trace.append(
            TraceEntry(
                stage="final_synthesis",
                component="orchestrator",
                status="DENY",
                reason_ids=missing_reason,
            )
        )

        reason_ids = missing_reason

        hash_material = {
            "request": asdict(request),
            "outcome": "DENY",
            "reason_ids": list(reason_ids),
            "trace": [asdict(t) for t in trace],
        }

        try:
            context_hash = compute_context_hash(hash_material)
        except (TypeError, ValueError) as e:
            # Canonicalization/hashing is part of the contract → explicit reason id
            raise TVAError(ReasonId.HASHING_FAILED.value, f"hashing failed: {e}") from e

        return OrchestratorV3Response.deny(
            context_hash=context_hash,
            reason_ids=reason_ids,
            trace=tuple(trace),
        )

    except TVAError as e:
        # Deterministic DENY for validation / hashing errors
        trace = (
            TraceEntry(
                stage="input_validation",
                component="orchestrator",
                status="DENY",
                reason_ids=(e.reason_id,),
            ),
        )

        hash_material = {
            "request": asdict(request),
            "outcome": "DENY",
            "reason_ids": [e.reason_id],
            "trace": [asdict(t) for t in trace],
        }

        # This must not throw; if it does, we fall back to INTERNAL_ERROR below.
        try:
            context_hash = compute_context_hash(hash_material)
        except Exception:
            context_hash = compute_context_hash(
                {
                    "request": {"contract_version": request.contract_version},
                    "outcome": "DENY",
                    "reason_ids": [ReasonId.INTERNAL_ERROR.value],
                    "trace": [{"stage": "input_validation", "component": "orchestrator", "status": "DENY"}],
                }
            )

        return OrchestratorV3Response.deny(
            context_hash=context_hash,
            reason_ids=(e.reason_id,),
            trace=trace,
        )

    except Exception:
        # Catch-all, deterministic
        trace = (
            TraceEntry(
                stage="input_validation",
                component="orchestrator",
                status="DENY",
                reason_ids=(ReasonId.INTERNAL_ERROR.value,),
            ),
        )

        hash_material = {
            "request": asdict(request),
            "outcome": "DENY",
            "reason_ids": [ReasonId.INTERNAL_ERROR.value],
            "trace": [asdict(t) for t in trace],
        }

        context_hash = compute_context_hash(hash_material)

        return OrchestratorV3Response.deny(
            context_hash=context_hash,
            reason_ids=(ReasonId.INTERNAL_ERROR.value,),
            trace=trace,
        )


def _validate_request(request: OrchestratorV3Request) -> None:
    if request.contract_version != CONTRACT_VERSION:
        raise TVAError(
            ReasonId.INVALID_CONTRACT_VERSION.value,
            "contract_version must be 3",
        )

    if not isinstance(request.wallet_id, str) or not request.wallet_id:
        raise TVAError(
            ReasonId.INVALID_REQUEST.value,
            "wallet_id must be a non-empty string",
        )

    if not isinstance(request.action, str) or not request.action:
        raise TVAError(
            ReasonId.INVALID_REQUEST.value,
            "action must be a non-empty string",
        )

    if not isinstance(request.nonce, str) or not request.nonce:
        raise TVAError(
            ReasonId.INVALID_REQUEST.value,
            "nonce must be a non-empty string",
        )

    if not isinstance(request.ttl_seconds, int) or request.ttl_seconds <= 0:
        raise TVAError(
            ReasonId.INVALID_REQUEST.value,
            "ttl_seconds must be a positive integer",
        )
