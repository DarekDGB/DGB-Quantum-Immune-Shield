from __future__ import annotations

from dataclasses import asdict

from shield_orchestrator.bridges.adaptive_core_bridge import AdaptiveCoreBridge
from shield_orchestrator.bridges.adn_bridge import ADNBridge
from shield_orchestrator.bridges.dqsn_bridge import DQSNBridge
from shield_orchestrator.bridges.guardian_wallet_bridge import GuardianWalletBridge
from shield_orchestrator.bridges.qwg_bridge import QWGBridge
from shield_orchestrator.bridges.sentinel_bridge import SentinelBridge
from shield_orchestrator.errors import TVAError

from .context_hash import compute_context_hash
from .contracts.envelope import OrchestratorV3Request, OrchestratorV3Response, TraceEntry
from .contracts.reason_ids import ReasonId
from .contracts.version import CONTRACT_VERSION


def orchestrate(request: OrchestratorV3Request) -> OrchestratorV3Response:
    """
    Orchestrator v3 public entrypoint.

    Phase 3 behavior:
    - strict request validation + contract_version gate
    - deterministic bridge calls in fixed order:
        Sentinel -> DQSN -> ADN -> Guardian Wallet -> QWG
    - deny-by-default synthesis (DENY_BY_POLICY) until real allow/escalate logic is integrated
    - Adaptive Core is a read-only sink and must not affect outcome
    - hashing/serialization failures map to HASHING_FAILED (fail-closed)
    """
    try:
        _validate_request(request)

        trace: list[TraceEntry] = [
            TraceEntry(stage="input_validation", component="orchestrator", status="OK")
        ]

        # Fixed, deterministic bridge order (no order dependence)
        try:
            trace.append(SentinelBridge().evaluate_v3(request))
            trace.append(DQSNBridge().evaluate_v3(request))
            trace.append(ADNBridge().evaluate_v3(request))
            trace.append(GuardianWalletBridge().evaluate_v3(request))
            trace.append(QWGBridge().evaluate_v3(request))
        except TypeError as e:
            # Most common: non-JSON-serializable payload encountered during hashing in a bridge stub.
            raise TVAError(ReasonId.HASHING_FAILED.value, "hashing failed") from e
        except Exception as e:
            raise TVAError(ReasonId.COMPONENT_ERROR.value, "component error") from e

        # Phase 3 synthesis: deny-by-default (contract reason id: DENY_BY_POLICY)
        outcome = "DENY"
        reason_ids = (ReasonId.DENY_BY_POLICY.value,)

        trace.append(
            TraceEntry(
                stage="final_synthesis",
                component="orchestrator",
                status="DENY",
                reason_ids=reason_ids,
            )
        )

        # Adaptive Core sink (must not influence outcome)
        try:
            sink_entry = AdaptiveCoreBridge().report_v3(
                request, outcome=outcome, reason_ids=reason_ids
            )
        except Exception:
            sink_entry = TraceEntry(
                stage="adaptive_core",
                component="adaptive_core",
                status="ERROR",
                reason_ids=(ReasonId.COMPONENT_ERROR.value,),
                notes="phase3_sink_failed",
            )

        full_trace = tuple(trace + [sink_entry])

        # Hash the full request material (including payload). If it fails -> HASHING_FAILED.
        try:
            hash_material = {
                "request": _request_for_hash(request, include_payload=True),
                "outcome": outcome,
                "reason_ids": list(reason_ids),
                "trace": [asdict(t) for t in full_trace],
            }
            context_hash = compute_context_hash(hash_material)
        except TypeError as e:
            raise TVAError(ReasonId.HASHING_FAILED.value, "hashing failed") from e

        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            outcome=outcome,
            context_hash=context_hash,
            reason_ids=reason_ids,
            trace=full_trace,
        )

    except TVAError as e:
        # Build a deterministic DENY response without ever re-hashing the payload.
        trace = (
            TraceEntry(
                stage="fail_closed",
                component="orchestrator",
                status="DENY",
                reason_ids=(e.reason_id,),
                notes="tva_error",
            ),
        )

        # Always omit payload in failure hashing to avoid recursive serialization errors.
        hash_material = {
            "request": _request_for_hash(request, include_payload=False),
            "outcome": "DENY",
            "reason_ids": [e.reason_id],
            "trace": [asdict(t) for t in trace],
        }
        context_hash = compute_context_hash(hash_material)

        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            outcome="DENY",
            context_hash=context_hash,
            reason_ids=(e.reason_id,),
            trace=trace,
        )

    except Exception:
        trace = (
            TraceEntry(
                stage="internal_error",
                component="orchestrator",
                status="DENY",
                reason_ids=(ReasonId.INTERNAL_ERROR.value,),
            ),
        )

        hash_material = {
            "request": _request_for_hash(request, include_payload=False),
            "outcome": "DENY",
            "reason_ids": [ReasonId.INTERNAL_ERROR.value],
            "trace": [asdict(t) for t in trace],
        }
        context_hash = compute_context_hash(hash_material)

        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            outcome="DENY",
            context_hash=context_hash,
            reason_ids=(ReasonId.INTERNAL_ERROR.value,),
            trace=trace,
        )


def _request_for_hash(request: OrchestratorV3Request, *, include_payload: bool) -> dict:
    """
    Deterministic request material for hashing.

    include_payload=True is the normal path.
    include_payload=False is used for fail-closed responses to avoid
    non-serializable payload causing recursive hashing failures.
    """
    d = asdict(request)
    if not include_payload:
        d = dict(d)
        d["payload"] = None
    return d


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
        raise TVAError(ReasonId.INVALID_REQUEST.value, "ttl_seconds must be a positive integer")
