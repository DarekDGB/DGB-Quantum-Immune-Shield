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
    - deny-by-default synthesis (no hidden allow paths yet)
    - Adaptive Core is a read-only sink that must not affect outcome
    """
    try:
        _validate_request(request)

        trace: list[TraceEntry] = []
        trace.append(
            TraceEntry(
                stage="input_validation",
                component="orchestrator",
                status="OK",
            )
        )

        # Fixed, deterministic bridge order (no order dependence)
        trace.append(SentinelBridge().evaluate_v3(request))
        trace.append(DQSNBridge().evaluate_v3(request))
        trace.append(ADNBridge().evaluate_v3(request))
        trace.append(GuardianWalletBridge().evaluate_v3(request))
        trace.append(QWGBridge().evaluate_v3(request))

        # Phase 3 synthesis: deny-by-default (until real allow/escalate logic is integrated)
        outcome = "DENY"
        reason_ids = (ReasonId.POLICY_DENY_BY_DEFAULT.value,)

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
            sink_entry = AdaptiveCoreBridge().report_v3(request, outcome=outcome, reason_ids=reason_ids)
        except Exception:
            sink_entry = TraceEntry(
                stage="adaptive_core",
                component="adaptive_core",
                status="ERROR",
                reason_ids=(ReasonId.TELEMETRY_FAILED.value,),
                notes="phase3_sink_failed",
            )

        full_trace = tuple(trace + [sink_entry])

        hash_material = {
            "request": asdict(request),
            "outcome": outcome,
            "reason_ids": list(reason_ids),
            "trace": [asdict(t) for t in full_trace],
        }

        context_hash = compute_context_hash(hash_material)

        return OrchestratorV3Response(
            contract_version=CONTRACT_VERSION,
            outcome=outcome,
            context_hash=context_hash,
            reason_ids=reason_ids,
            trace=full_trace,
        )

    except TVAError as e:
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
            "request": asdict(request),
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
