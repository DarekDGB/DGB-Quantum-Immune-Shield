from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from typing import Any, Protocol, TypeVar

from shield_orchestrator.v4.canonical_json import COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN
from shield_orchestrator.v4.crypto_algorithms import (
    SIGNATURE_POLICY_V1,
    require_supported_standard_profile as _policy_require_supported_standard_profile,
)
from shield_orchestrator.v4.key_registry import KeyRegistryEntry
from shield_orchestrator.v4.work_budget import MAX_TEXT_FIELD_BYTES

REAL_CRYPTO_SIGNATURE_INPUT_PREFIX = "DGB-SHIELD-V4-REAL-CRYPTO-SIGNATURE-INPUT"
REAL_SIGNATURE_ENCODING_PREFIX = "b64u:"
_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_ALLOWED_DOMAIN_TAGS = frozenset({COMPONENT_VERDICT_DOMAIN, ORCHESTRATOR_RECEIPT_DOMAIN})
_SIGNATURE_ENTRY_FIELDS = frozenset({"algorithm", "standard_profile", "key_id", "key_version", "signed_payload_hash", "domain_tag", "signature"})
_T = TypeVar("_T")
_TEST_ONLY_MARKERS = ("test-only",)
_TEST_ONLY_PREFIXES = ("test-",)


class ShieldV4RealCryptoBackendError(ValueError):
    """Base fail-closed error for Shield v4 real crypto backend wiring."""


class ShieldV4RealCryptoBackendUnavailable(ShieldV4RealCryptoBackendError):
    """Raised when a required production backend/algorithm is not available."""


class ShieldV4RealCryptoMaterialError(ShieldV4RealCryptoBackendError):
    """Raised when test-only material reaches the real-crypto adapter boundary."""


class ShieldV4RealCryptoBackend(Protocol):
    """Minimal production crypto backend contract for Shield v4 signatures.

    Implementations may wrap liboqs, a FIPS-validated module, an HSM, or another
    deployment-controlled backend. This protocol intentionally avoids importing a
    concrete PQC library so CI cannot silently depend on a local machine backend.
    """

    backend_name: str
    backend_version: str
    supported_algorithms: tuple[str, ...]

    def sign_message(self, *, algorithm: str, private_key_reference: str, message: bytes) -> str:
        """Return a signature encoding for the supplied message."""

    def verify_signature(
        self,
        *,
        algorithm: str,
        public_key: str,
        message: bytes,
        signature: str,
    ) -> bool:
        """Return True only when the signature verifies under the supplied public key."""


RealCryptoSignatureVerifier = Callable[[dict[str, Any], KeyRegistryEntry], bool]


def _require_non_empty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ShieldV4RealCryptoBackendError(f"{field} must be non-empty string")
    if value != value.strip():
        raise ShieldV4RealCryptoBackendError(f"{field} must not contain surrounding whitespace")
    return value


def _call_backend_operation(operation: str, callback: Callable[[], _T]) -> _T:
    try:
        return callback()
    except ShieldV4RealCryptoBackendError:
        raise
    except Exception as exc:
        raise ShieldV4RealCryptoBackendError(f"real crypto backend {operation} failed closed") from exc


def _require_positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ShieldV4RealCryptoBackendError(f"{field} must be positive integer")
    return value


def _require_supported_algorithm(value: Any) -> str:
    algorithm = _require_non_empty_str(value, field="algorithm")
    if algorithm not in SIGNATURE_POLICY_V1.allowed_algorithms:
        raise ShieldV4RealCryptoBackendError("unsupported Shield v4 signature algorithm")
    return algorithm
def _require_supported_standard_profile(*, algorithm: str, standard_profile: str) -> str:
    try:
        return _policy_require_supported_standard_profile(
            algorithm=algorithm,
            standard_profile=standard_profile,
        )
    except ValueError as exc:
        raise ShieldV4RealCryptoBackendError(str(exc)) from exc


def _require_hash(value: Any, *, field: str) -> str:
    clean = _require_non_empty_str(value, field=field)
    if len(clean) != 64:
        raise ShieldV4RealCryptoBackendError(f"{field} must be 64-character sha256 hex")
    try:
        int(clean, 16)
    except ValueError as exc:
        raise ShieldV4RealCryptoBackendError(f"{field} must be sha256 hex") from exc
    if clean != clean.lower():
        raise ShieldV4RealCryptoBackendError(f"{field} must be lowercase sha256 hex")
    return clean


def _reject_test_only_text(value: str, *, field: str) -> None:
    clean = value.strip().lower()
    if any(marker in clean for marker in _TEST_ONLY_MARKERS) or any(
        clean.startswith(prefix) for prefix in _TEST_ONLY_PREFIXES
    ):
        raise ShieldV4RealCryptoMaterialError(f"{field} must not contain test-only material")


def reject_test_only_key_material(key: KeyRegistryEntry) -> None:
    """Fail closed if deterministic-test keys reach the real backend boundary."""

    _reject_test_only_text(key.key_id, field="key_id")
    _reject_test_only_text(key.public_key, field="public_key")


def reject_test_only_private_key_reference(private_key_reference: str) -> str:
    clean = _require_non_empty_str(private_key_reference, field="private_key_reference")
    _reject_test_only_text(clean, field="private_key_reference")
    return clean


def encode_binary_signature_material(raw: bytes, *, field: str = "signature") -> str:
    """Encode real binary signature/key material using unpadded base64url.

    Real ML-DSA signatures and public keys are binary and substantially larger than
    the historical deterministic 64-character test digests. The explicit ``b64u:``
    prefix prevents silently confusing real signatures with test-only digest strings.
    """

    if not isinstance(raw, bytes) or not raw:
        raise ShieldV4RealCryptoBackendError(f"{field} bytes must be non-empty")
    maximum_raw_bytes = ((MAX_TEXT_FIELD_BYTES - len(REAL_SIGNATURE_ENCODING_PREFIX)) * 3) // 4
    if len(raw) > maximum_raw_bytes:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u encoding exceeds byte limit")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    output = f"{REAL_SIGNATURE_ENCODING_PREFIX}{encoded}"
    if len(output) > MAX_TEXT_FIELD_BYTES:  # pragma: no cover - defensive arithmetic lock.
        raise ShieldV4RealCryptoBackendError(f"{field} b64u encoding exceeds byte limit")
    return output


def _require_bounded_encoded_text(encoded: Any, *, field: str) -> str:
    if type(encoded) is not str or not encoded:
        raise ShieldV4RealCryptoBackendError(f"{field} must be non-empty string")
    if len(encoded) > MAX_TEXT_FIELD_BYTES:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u encoding exceeds byte limit")
    try:
        encoded_bytes = encoded.encode("utf-8")
    except UnicodeEncodeError:
        raise ShieldV4RealCryptoBackendError(
            f"{field} b64u encoding must be valid UTF-8"
        ) from None
    if len(encoded_bytes) > MAX_TEXT_FIELD_BYTES:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u encoding exceeds byte limit")
    return encoded


def decode_binary_signature_material(encoded: Any, *, field: str = "signature") -> bytes:
    """Decode an explicit ``b64u:`` signature/key encoding into bytes."""

    encoded = _require_bounded_encoded_text(encoded, field=field)
    clean = _require_non_empty_str(encoded, field=field)
    if not clean.startswith(REAL_SIGNATURE_ENCODING_PREFIX):
        raise ShieldV4RealCryptoBackendError(f"{field} must use b64u encoding")
    body = clean[len(REAL_SIGNATURE_ENCODING_PREFIX) :]
    if not body:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload must be non-empty")
    if "=" in body:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload must be unpadded")
    if set(body) - _BASE64URL_ALPHABET:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload is invalid")
    try:
        decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload is invalid") from exc
    if not decoded:  # pragma: no cover - base64url cannot reach this after the body check.
        raise ShieldV4RealCryptoBackendError(f"{field} b64u payload must decode to non-empty bytes")
    return decoded


def build_real_crypto_signature_input(
    *,
    algorithm: str,
    standard_profile: str,
    domain_tag: str,
    signed_payload_hash: str,
    key_id: str,
    key_version: int,
) -> bytes:
    """Build the exact production-signature message bytes for Shield v4.

    The signed payload hash is already domain-separated over the canonical JSON
    payload. The backend message binds that hash to the signature role, algorithm,
    standard profile, key id, and key version so entries cannot be spliced across
    bundles or reinterpreted under another FN-DSA/Falcon profile.
    """

    clean_algorithm = _require_supported_algorithm(algorithm)
    clean_domain = _require_non_empty_str(domain_tag, field="domain_tag")
    if clean_domain not in _ALLOWED_DOMAIN_TAGS:
        raise ShieldV4RealCryptoBackendError("domain_tag must be a Shield v4 signing domain")
    clean_profile = _require_supported_standard_profile(
        algorithm=clean_algorithm,
        standard_profile=_require_non_empty_str(standard_profile, field="standard_profile"),
    )
    clean_hash = _require_hash(signed_payload_hash, field="signed_payload_hash")
    clean_key_id = _require_non_empty_str(key_id, field="key_id")
    clean_key_version = _require_positive_int(key_version, field="key_version")
    return "\n".join(
        (
            REAL_CRYPTO_SIGNATURE_INPUT_PREFIX,
            clean_domain,
            clean_hash,
            clean_algorithm,
            clean_profile,
            clean_key_id,
            str(clean_key_version),
        )
    ).encode("utf-8")


def _require_backend_supports_algorithm(backend: ShieldV4RealCryptoBackend, algorithm: str) -> None:
    try:
        supported = tuple(getattr(backend, "supported_algorithms", ()))
    except Exception as exc:
        raise ShieldV4RealCryptoBackendError("real crypto backend algorithm discovery failed closed") from exc
    if algorithm not in supported:
        raise ShieldV4RealCryptoBackendUnavailable("real crypto backend does not support required algorithm")


def build_signature_entry_with_real_backend(
    *,
    algorithm: str,
    standard_profile: str,
    domain_tag: str,
    signed_payload_hash: str,
    key_id: str,
    key_version: int,
    private_key_reference: str,
    backend: ShieldV4RealCryptoBackend,
) -> dict[str, Any]:
    """Build a Shield v4 signature entry using a real backend implementation."""

    clean_algorithm = _require_supported_algorithm(algorithm)
    clean_domain = _require_non_empty_str(domain_tag, field="domain_tag")
    clean_profile = _require_supported_standard_profile(
        algorithm=clean_algorithm,
        standard_profile=_require_non_empty_str(standard_profile, field="standard_profile"),
    )
    clean_hash = _require_hash(signed_payload_hash, field="signed_payload_hash")
    clean_key_id = _require_non_empty_str(key_id, field="key_id")
    clean_key_version = _require_positive_int(key_version, field="key_version")
    message = build_real_crypto_signature_input(
        algorithm=clean_algorithm,
        standard_profile=clean_profile,
        domain_tag=clean_domain,
        signed_payload_hash=clean_hash,
        key_id=clean_key_id,
        key_version=clean_key_version,
    )
    clean_private_ref = reject_test_only_private_key_reference(private_key_reference)
    _require_backend_supports_algorithm(backend, clean_algorithm)
    signature = _call_backend_operation(
        "sign",
        lambda: backend.sign_message(
            algorithm=clean_algorithm,
            private_key_reference=clean_private_ref,
            message=message,
        ),
    )
    decode_binary_signature_material(signature, field="signature")
    clean_signature = _require_non_empty_str(signature, field="signature")
    return {
        "algorithm": clean_algorithm,
        "standard_profile": clean_profile,
        "key_id": clean_key_id,
        "key_version": clean_key_version,
        "signed_payload_hash": clean_hash,
        "domain_tag": clean_domain,
        "signature": clean_signature,
    }


def verify_signature_entry_with_real_backend(
    entry: dict[str, Any],
    key: KeyRegistryEntry,
    *,
    backend: ShieldV4RealCryptoBackend,
) -> bool:
    """Verify one Shield v4 signature entry with a production backend."""

    if not isinstance(entry, dict):
        raise ShieldV4RealCryptoBackendError("signature entry must be dict")
    if set(entry.keys()) != _SIGNATURE_ENTRY_FIELDS:
        raise ShieldV4RealCryptoBackendError("signature entry fields must match required schema")
    _require_bounded_encoded_text(entry.get("signature"), field="signature")
    _require_bounded_encoded_text(key.public_key, field="public_key")
    reject_test_only_key_material(key)
    decode_binary_signature_material(entry.get("signature"), field="signature")
    decode_binary_signature_material(key.public_key, field="public_key")
    algorithm = _require_supported_algorithm(entry.get("algorithm"))
    standard_profile = _require_supported_standard_profile(
        algorithm=algorithm,
        standard_profile=_require_non_empty_str(entry.get("standard_profile"), field="standard_profile"),
    )
    key_id = _require_non_empty_str(entry.get("key_id"), field="key_id")
    key_version = _require_positive_int(entry.get("key_version"), field="key_version")
    if (key.algorithm, key.key_id, key.key_version) != (algorithm, key_id, key_version):
        raise ShieldV4RealCryptoBackendError("signature entry does not match registry key")
    public_key = _require_non_empty_str(key.public_key, field="public_key")
    _require_backend_supports_algorithm(backend, algorithm)
    message = build_real_crypto_signature_input(
        algorithm=algorithm,
        standard_profile=standard_profile,
        domain_tag=_require_non_empty_str(entry.get("domain_tag"), field="domain_tag"),
        signed_payload_hash=_require_hash(entry.get("signed_payload_hash"), field="signed_payload_hash"),
        key_id=key_id,
        key_version=key_version,
    )
    signature = _require_non_empty_str(entry.get("signature"), field="signature")
    verified = _call_backend_operation(
        "verify",
        lambda: backend.verify_signature(
            algorithm=algorithm,
            public_key=public_key,
            message=message,
            signature=signature,
        ),
    )
    if not isinstance(verified, bool):
        raise ShieldV4RealCryptoBackendError("real crypto backend verify must return bool")
    return verified


def make_real_crypto_signature_verifier(
    backend: ShieldV4RealCryptoBackend,
) -> RealCryptoSignatureVerifier:
    """Adapt a real crypto backend to the existing Shield v4 bundle verifier."""

    def _verify(entry: dict[str, Any], key: KeyRegistryEntry) -> bool:
        return verify_signature_entry_with_real_backend(entry, key, backend=backend)

    return _verify
