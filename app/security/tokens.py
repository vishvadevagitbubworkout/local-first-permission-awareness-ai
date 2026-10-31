"""Capability token claims, signing, and key management."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.security.capabilities import APPROVED_CAPABILITY_TEMPLATE_MAP
from app.security.permissions import PermissionScope

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

_RESOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,127}$")

_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

_MAC = re.compile(r"^[0-9a-f]{64}$")

class UsagePolicy(str, Enum):
    ONE_TIME = "ONE_TIME"
    REPEATABLE = "REPEATABLE"

class _ImmutableMapping(dict):
    def _blocked(self, *args, **kwargs):
        raise TypeError("capability constraints are immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _blocked

    def __deepcopy__(self, memo):
        return self

def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return _ImmutableMapping({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    if isinstance(value, tuple):
        return tuple(_freeze(child) for child in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise ValueError("constraints must contain only JSON-compatible values")

class CapabilityClaims(BaseModel):
    """Immutable unsigned capability claims reserved for later M5 authentication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str = Field(..., min_length=1)
    task_id: str = Field(..., min_length=1)
    step_id: str = Field(..., min_length=1)
    agent: str = Field(..., min_length=1)
    operation: str = Field(..., min_length=1)
    resource: str = Field(..., min_length=1)
    scope: PermissionScope
    constraints: Mapping[str, Any] = Field(default_factory=dict)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(..., min_length=16, max_length=128)
    usage_policy: UsagePolicy

    def model_copy(self, *, update=None, deep=False):
        if update:
            raise TypeError("CapabilityClaims cannot be retagged after creation")
        return super().model_copy(update=None, deep=deep)

    @field_validator("capability_id", "task_id", "step_id", "agent", "operation")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        normalized = value.strip()
        if normalized != value or not _IDENTIFIER.fullmatch(normalized):
            raise ValueError("capability identifiers must use the established safe identifier format")
        return normalized

    @field_validator("resource")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        normalized = value.strip()
        if normalized != value or not _RESOURCE.fullmatch(normalized) or ".." in normalized:
            raise ValueError("resource must be a bounded relative resource label")
        return normalized

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, value: str) -> str:
        if not _NONCE.fullmatch(value):
            raise ValueError("nonce must be a 16-128 character URL-safe value")
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("capability timestamps must be timezone-aware")
        return value

    @field_validator("constraints", mode="after")
    @classmethod
    def validate_constraints(cls, value: Any) -> Mapping[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("constraints must be a JSON object")
        if any(not isinstance(key, str) or not key.strip() for key in value):
            raise ValueError("constraint keys must be non-empty strings")
        return _freeze(value)

    @model_validator(mode="after")
    def validate_claim_relationships(self) -> "CapabilityClaims":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        template = APPROVED_CAPABILITY_TEMPLATE_MAP.get(self.capability_id)
        if template is None:
            raise ValueError("capability_id must reference an approved M3 capability")
        if self.agent != template.agent:
            raise ValueError("agent does not match the approved capability")
        if self.operation.upper() != template.operation.upper():
            raise ValueError("operation does not match the approved capability")
        if self.scope.resource_type != template.resource_type:
            raise ValueError("scope resource type does not match the approved capability")
        return self

class AuthenticatedCapability(BaseModel):
    """Immutable claims plus the M5.2 authentication tag."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claims: CapabilityClaims
    mac: str = Field(..., min_length=64, max_length=64)

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, value: str) -> str:
        if not _MAC.fullmatch(value):
            raise ValueError("mac must be a lowercase hexadecimal SHA-256 HMAC")
        return value

    def model_copy(self, *, update=None, deep=False):
        if update:
            raise TypeError("AuthenticatedCapability cannot be retagged after minting")
        return super().model_copy(update=None, deep=deep)

def _canonical_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        normalized = value.astimezone(timezone.utc)
        return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"Unsupported canonical value type: {type(value).__name__}")

def claims_payload(claims: CapabilityClaims) -> dict[str, Any]:
    if not isinstance(claims, CapabilityClaims):
        raise TypeError("claims_payload expects CapabilityClaims")

    return {
        "agent": claims.agent,
        "capability_id": claims.capability_id,
        "constraints": _canonical_value(claims.constraints),
        "expires_at": _canonical_value(claims.expires_at),
        "issued_at": _canonical_value(claims.issued_at),
        "nonce": claims.nonce,
        "operation": claims.operation,
        "resource": claims.resource,
        "scope": {
            "kind": claims.scope.kind.value,
            "resource_id": claims.scope.resource_id,
            "resource_type": claims.scope.resource_type.value,
            "selector": claims.scope.selector,
        },
        "step_id": claims.step_id,
        "task_id": claims.task_id,
        "usage_policy": claims.usage_policy.value,
    }

def canonicalize_claims(claims: CapabilityClaims) -> bytes:
    """Serialize all immutable capability claims into deterministic UTF-8 JSON bytes.

    Contract: the complete fixed field set from ``claims_payload`` is included;
    JSON objects use lexicographically sorted keys, lists preserve their order,
    enums use their string values, datetimes use UTC ISO-8601 with six fractional
    digits and a trailing ``Z``, nulls are retained, and UTF-8 is used with
    compact separators and no ASCII escaping. No lifecycle state or secret key
    is part of the payload.
    """
    payload = claims_payload(claims)
    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return serialized.encode("utf-8")

_MIN_KEY_BYTES = 32

def _validate_key(secret_key: bytes) -> bytes:
    if not isinstance(secret_key, bytes):
        raise TypeError("secret_key must be bytes")
    if len(secret_key) < _MIN_KEY_BYTES:
        raise ValueError("secret_key must contain at least 32 bytes")
    return secret_key

def compute_mac(claims: CapabilityClaims, secret_key: bytes) -> str:
    """Return the hex HMAC-SHA256 for the complete canonical claims payload."""
    key = _validate_key(secret_key)
    return hmac.new(key, canonicalize_claims(claims), hashlib.sha256).hexdigest()

def verify_mac(claims: CapabilityClaims, secret_key: bytes, mac: str) -> bool:
    """Compare a supplied MAC in constant time without authorization decisions."""
    if not isinstance(mac, str):
        return False
    try:
        expected = compute_mac(claims, secret_key)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, mac)

_DEFAULT_KEY_DIR = Path.home() / ".local" / "permission_aware_automation"

_DEFAULT_KEY_FILE = _DEFAULT_KEY_DIR / "capability_hmac.key"

_ENV_KEY = "CAPABILITY_HMAC_KEY"

class CapabilityKeyProvider:
    """M5-owned source of the capability signing secret."""

    def __init__(self, *, secret_key: bytes | None = None):
        if secret_key is not None:
            self._secret_key = _validate_key(secret_key)
            self._owned = False
        else:
            self._secret_key = _load_or_create_persistent_key()
            self._owned = True

    def get_signing_key(self) -> bytes:
        return self._secret_key

    @classmethod
    def for_testing(cls, secret_key: bytes) -> "CapabilityKeyProvider":
        """Create a provider with a deterministic key for tests only."""
        return cls(secret_key=secret_key)

def _load_or_create_persistent_key() -> bytes:
    env_value = os.environ.get(_ENV_KEY)
    if env_value:
        return _validate_key(env_value.encode("utf-8"))

    if _DEFAULT_KEY_FILE.is_file():
        return _validate_key(_DEFAULT_KEY_FILE.read_bytes())

    _DEFAULT_KEY_DIR.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    _DEFAULT_KEY_FILE.write_bytes(key)
    return key

__all__ = [
    'AuthenticatedCapability',
    'CapabilityClaims',
    'UsagePolicy',
    'canonicalize_claims',
    'claims_payload',
    'compute_mac',
    'verify_mac',
    'CapabilityKeyProvider',
]
