from __future__ import annotations

from dataclasses import asdict

from shield_orchestrator.errors import TVAError

from .contracts.envelope import OrchestratorV3Request, OrchestratorV3Response, TraceEntry
from .contracts.reason_ids import ReasonId
from .contracts.version import CONTRACT_VERSION
from .context_hash import compute_context_hash


_COMPONENT_ORDER: tuple[tuple[str, str], ...] = (
    ("sentinel_ai", "sentinel_ai"),
    ("dqsn", "dqsn"),
    ("adn", "adn"),
    ("qwg", "qwg"),
    ("guardian_wallet", "guardian_wallet"),
)


def orchestrate(request: OrchestratorV3Request) -> OrchestratorV3Response:
    """
    Public v3 entrypoint.

    Phase 2 behavior:
    - strict request validation
    - deterministic trace skeleton (components marked missing)
    - fail-closed DENY

    Phase 3/4 will replace the "missing component" behavior with real bridge calls.
    """
    try:
        _validate_request(request)

        trace: list[TraceEntry] = []
        trace.append(
            TraceEntry(
                stage="input_validation",
                component="orchestrator",
                status="OK",
                reason_ids=(),
                component_context_hash=None,
                notes=None,
            )
        )

        # Phase 2: components not yet wired -> represent deterministic missing.
        missing_reason = (ReasonId.COMPONENT_MISSING.value,)
        for stage, component in _COMPONENT_ORDER:
            trace.append(
                TraceEntry(
                    stage=stage,
                    component=component,
                    status="ERROR",
                    reason_ids=missing_reason,
                    component_context_hash=None,
                    notes="phase2_unwired",
                )
            )

        # Final synthesis: deny-by-default since required components are missing.
        trace.append(
            TraceEntry(
                stage="final_synthesis",
                component="orchestrator",
                status="DENY",
                reason_ids=missing_reason,
                component_context_hash=None,
                notes=None,
            )
        )

        # Hash material is contract-defined: request + trace + outcome + reason_ids.
        reason_ids = missing_reason
        hash_material = {
            "request": asdict(request),
            "outcome": "DENY",
            "reason_ids": list(reason_ids),
            "trace": [asdict(t) for t in trace],
        }
        ctx_hash = compute_context_hash(hash_material)
        return OrchestratorV3Response.deny(
            context_hash=ctx_hash,
            reason_ids=reason_ids,
            trace=tuple(trace),
        )

    except TVAError as e:
        # Convert to deterministic DENY envelope
        trace = (
            TraceEntry(
                stage="input_validation",
                component="orchestrator",
                status="DENY",
                reason_ids=(e.reason_id,),
                component_context_hash=None,
                notes=None,
            ),
        )
        hash_material = {
            "request": asdict(request),
            "outcome": "DENY",
            "reason_ids": [e.reason_id],
            "trace": [asdict(t) for t in trace],
        }
        ctx_hash = compute_context_hash(hash_material)
        return OrchestratorV3Response.deny(
            context_hash=ctx_hash,
            reason_ids=(e.reason_id,),
            trace=trace,
        )
    except Exception:
        # Deterministic catch-all
        trace = (
            TraceEntry(
                stage="input_validation",
                component="orchestrator",
                status="DENY",
                reason_ids=(ReasonId.INTERNAL_ERROR.value,),
                component_context_hash=None,
                notes=None,
            ),
        )
        hash_material = {
            "request": asdict(request),
            "outcome": "DENY",
            "reason_ids": [ReasonId.INTERNAL_ERROR.value],
            "trace": [asdict(t) for t in trace],
        }
        ctx_hash = compute_context_hash(hash_material)
        return OrchestratorV3Response.deny(
            context_hash=ctx_hash,
            reason_ids=(ReasonId.INTERNAL_ERROR.value,),
            trace=trace,
        )


def _validate_request(request: OrchestratorV3Request) -> None:
    if request.contract_version != CONTRACT_VERSION:
        raise TVAError(ReasonId.INVALID_CONTRACT_VERSION.value, "contract_version must be 3")

    if not isinstance(request.wallet_id, str) or not request.wallet_id:
        raise TVAError(ReasonId.INVALID_REQUEST.value, "wallet_id must be a non-empty string")

    if not isinstance(request.action, str) or not request.action:
        raise TVAError(ReasonId.INVALID_REQUEST.value, "action must be a non-empty string")

    if not isinstance(request.nonce, str) or not request.nonce:
        raise TVAError(ReasonId.INVALID_REQUEST.value, "nonce must be a non-empty string")

    if not isinstance(request.ttl_seconds, int) or request.ttl_seconds <= 0:
        raise TVAError(ReasonId.INVALID_REQUEST.value, "ttl_seconds must be a positive int")
