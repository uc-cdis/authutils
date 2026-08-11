"""
DPoP (Demonstrating Proof-of-Possession) RFC 9449 implementation.

This module provides centralized DPoP functionality for:

- Client-side proof generation (Gen3 ex: gen3sdk-python)
- Resource server validation (Gen3 ex: gen3-workflow)
- Authorization server validation (Gen3 ex: fence)

Key concepts per RFC 9449:
- htm: HTTP method of the request
- htu: HTTP target URI (host + path, without query string)
- ath: Access token hash
- jti: Unique identifier for the proof
- cnf.jkt: Key thumbprint binding in the access token

This module integrates with authutils.token.core for comprehensive access token
validation (signature, expiration, issuer, scope, purpose), allowing services to
validate both the DPoP proof AND the access token in a single operation.
"""

import hashlib
import json
import os
import base64
import time
from collections.abc import Callable, Collection
from typing import Any
from urllib.parse import urlsplit

from cdislogging import get_logger
from joserfc import jwt, jwk, jws
from joserfc.errors import JoseError

from authutils.token.dpop_nonce import verify_stateless_nonce, generate_stateless_nonce
from authutils.token import core as token_core
from authutils.token.keys import get_any_public_key_for_token_async
from authutils.errors import (
    InvalidNonceErrorResourceServer,
    InvalidNonceErrorAuthorizationServer,
)

DPOP_JWT_TYPE = "dpop+jwt"

# frozenset, not set: joserfc treats a falsy `algorithms` collection as
# "allow every recommended algorithm" (which includes HS256), so an empty
# allowlist would silently disable algorithm pinning entirely. Making this
# immutable removes the possibility of it being cleared after import.
SUPPORTED_DPOP_ALGS = frozenset(
    {
        # EC
        "ES256",
        "ES384",
        "ES512",
        # RSA
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
    }
)

# Maps an EC curve to its one legal JWS algorithm (RFC 7518 3.4). ES256 is only
# valid with P-256, ES384 only with P-384, etc., so the proof alg cannot be
# chosen from the key type alone.
EC_CURVE_TO_ALG = {
    "P-256": "ES256",
    "P-384": "ES384",
    "P-521": "ES512",
}


# Curves permitted for DPoP proof keys.
ALLOWED_EC_CURVES = frozenset(EC_CURVE_TO_ALG)

# Minimum acceptable RSA modulus size, in bits. joserfc only emits a warning
# below 2048.
# DPoP proof keys get bound into access tokens via cnf.jkt, so a
# weak key would weaken every token bound to it.
MIN_RSA_KEY_BITS = 2048

# Will invalidate any proof older than 5 minutes
#
# NOTE: RFC 9449 11.1 recommends "a relatively brief period on the order of
# seconds or minutes". 300s is the outer edge of that. Because this module
# cannot itself track jti values across processes, deployments that want a
# tighter replay window should lower this AND supply a jti_seen_callback.
DPOP_PROOF_MAX_TTL = 300

# Will invalidate any proof created more than 60 seconds into the future
# this provides some leeway for clock skewing across client / server
DPOP_PROOF_CLOCK_SKEW_LEEWAY = 60

# To avoid unnecessarilly large JTIs since we may
# want to cache these in the future
MAX_JTI_LENGTH = 256

# Upper bound on the DPoP header we will even attempt to parse. Guards against
# a caller handing us an unbounded string before any crypto work happens.
MAX_DPOP_HEADER_LENGTH = 8192

# Default ports that are semantically equivalent to being absent, per RFC 9110
# 4.2. Stripping these keeps htu comparison stable behind proxies that add an
# explicit :443 to the Host header.
DEFAULT_PORTS_BY_SCHEME = {"http": "80", "https": "443"}

logging = get_logger(__name__)


def generate_dpop_proof(
    key: jwk.Key,
    method: str,
    url: str,
    access_token: str | None = None,
    nonce: str | None = None,
    alg: str | None = None,
) -> str:
    """
    Generate a DPoP proof JWT for a request.

    Args:
        key (jwk.Key): The asymmetric key for signing the proof.
        method (str): HTTP method (e.g., "GET", "POST").
        url (str): Full URL being requested (htu claim).
        access_token (str | None): Optional access token for ath claim calculation.
        nonce (str | None): Optional server nonce to include in the proof.
        alg (str | None): Optional explicit JWS algorithm. Must be one of
            SUPPORTED_DPOP_ALGS. If None, resolved from the key's type/curve.

    Returns:
        str: Encoded DPoP proof JWT string.

    Raises:
        ValueError: If the key type/curve is unsupported, the requested alg is
            not permitted for DPoP, or the access_token is scheme-prefixed.

    Example:
        >>> key = jwk.generate_key("EC", "P-256", private=True)
        >>> proof = generate_dpop_proof(
        ...     key,
        ...     "POST",
        ...     "https://fence.example.com/credentials/api/access_token",
        ... )
    """
    if alg is None:
        alg = _resolve_proof_alg(key)
    elif alg not in SUPPORTED_DPOP_ALGS:
        # Validate caller-supplied algs against our own allowlist rather than
        # relying on joserfc's broader "recommended" filter, so that e.g.
        # "none" and "HS256" fail here with a clear DPoP-specific error.
        raise ValueError(
            f"Unsupported or unpermitted DPoP signature algorithm: {alg}. "
            f"Allowed: {sorted(SUPPORTED_DPOP_ALGS)}"
        )

    header = {
        "typ": DPOP_JWT_TYPE,
        "alg": alg,
        "jwk": key.as_dict(private=False),
    }
    payload: dict[str, Any] = {
        "jti": os.urandom(16).hex(),
        "htm": method.upper(),
        "htu": _get_url(url),
        "iat": int(time.time()),
    }

    if access_token:
        _reject_bearer_prefixed_token(access_token)
        payload["ath"] = compute_ath(access_token)

    if nonce:
        payload["nonce"] = nonce

    return jwt.encode(header, payload, key, registry=_new_registry())


async def validate_dpop_request_async(
    dpop_header: str,
    access_token: str,
    request_method: str,
    request_url: str,
    issuers: list[str],
    public_key: str | bytes | None = None,
    scope: set[str] | list[str] | None = None,
    purpose: str | None = None,
    aud: str | None = None,
    require_nonce: bool = False,
    options: dict | None = None,
    denylist_callback: Callable | None = None,
    jti_seen_callback: Callable | None = None,
    secret: str | None = None,
    as_resource_server: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], jwk.Key]:
    """
    Validate both the DPoP proof AND the access token in one operation.

    This is a convenience function that combines:
    - DPoP proof validation (signature, htm, htu, ath, nonce)
        - Including: Key binding validation (proof key thumbprint == token cnf.jkt)
    - Access token validation

    This allows a service to blindly forward the DPoP header and Authorization
    header and get complete validation done in one call.

    Args:
        dpop_header (str): The DPoP proof JWT string from the DPoP header.
        access_token (str): The JWT access token string from the Authorization header.
        request_method (str): The HTTP method of the incoming request.
        request_url (str): The full URL of the incoming request (scheme + host +
            path), as the CLIENT saw it.
        issuers (list[str]): Allowed token issuers whitelist, exact-matched
            BEFORE any key discovery. Required and non-empty: `iss` is an
            unverified claim, so this list is what keeps an attacker from
            choosing which host key discovery contacts.
        public_key (str | bytes | None): Optional public key for token validation. If None, will be
            fetched from the token issuer's JWKS endpoint.
        scope (set[str] | list[str] | None): Optional required scopes that the token must satisfy.
        purpose (str | None): Optional required purpose (e.g., "access"). Must match token's pur claim.
        aud (str | None): Optional audience. Note: authutils no longer validates audience.
        require_nonce (bool): Whether to require and validate a DPoP nonce.
        options (dict | None): options to pass through to pyjwt's decode
        denylist_callback (Callable | None): a callback function that takes
          (jti: str) and returns True if the token is denylisted.
          The callback is called after basic JWT validation.
        jti_seen_callback (Callable | None): a callback taking the DPoP proof's
          (jti: str) and returning True if that jti has already been used.
          Enables RFC 9449 11.1 single-use replay protection, which this module
          cannot provide on its own because it holds no cross-process state.
        secret (str | None): Optional secret key for stateless nonce verification.
            If None, defaults to the environment-configured secret.
        as_resource_server (bool): Default True. Whether caller is a Resource Server.
            False implies caller is the Authorization Server. This alters some of the
            error messaging behavior (per the spec).

    Returns:
        dict[str, Any], dict[str, Any], jwk.Key:
            dict with decoded and validated claims dict from dpop,
            dict with decoded and validated claims dict from access token,
            validated client_jwk from dpop header

    Raises:
        ValueError: If DPoP proof validation fails, or if inputs are missing/malformed.
        JWTError: If access token validation fails (signature, expiration, issuer, scope, purpose).
        InvalidNonceError: If nonce is missing or invalid. This will contain the error,
            description, and a valid nonce for the caller to send back to client as
            header (per spec). Caller must extract the information from this exception.
    """
    if not dpop_header:
        raise ValueError("Invalid DPoP proof: Empty string / None provided")
    if not access_token:
        raise ValueError("Invalid access token: Empty string / None provided")

    _reject_bearer_prefixed_token(access_token)

    dpop_claims, client_jwk = validate_dpop_proof(
        dpop_header=dpop_header,
        request_method=request_method,
        request_url=request_url,
        unvalidated_access_token=access_token,
        require_nonce=require_nonce,
        secret=secret,
        as_resource_server=as_resource_server,
        jti_seen_callback=jti_seen_callback,
    )

    if not public_key:
        # Enforce the issuer allowlist against the UNVERIFIED iss before doing
        # any key discovery.
        public_key = await get_any_public_key_for_token_async(
            access_token, allowed_issuers=issuers
        )

    if isinstance(scope, list):
        scope = set(scope)

    validated_access_token_claims = token_core.validate_jwt(
        encoded_token=access_token,
        public_key=public_key,
        aud=aud,
        scope=scope,
        allowed_issuers=issuers,
        purpose=purpose,
        options=options,
        denylist_callback=denylist_callback,
    )

    return dpop_claims, validated_access_token_claims, client_jwk


def validate_dpop_proof(
    dpop_header: str,
    request_method: str,
    request_url: str,
    unvalidated_access_token: str | None = None,
    require_nonce: bool = False,
    secret: str | None = None,
    as_resource_server: bool = True,
    jti_seen_callback: Callable | None = None,
) -> tuple[dict[str, Any], jwk.Key]:
    """
    Validate a DPoP proof JWT for a resource server request.

    IMPORTANT: This DOES NOT validate the unvalidated_access_token beyond the validation
               of it being bound to the DPoP Proof. e.g. you MUST separately
               validate the access token and any additional authorization.

    This function performs comprehensive validation of a DPoP proof including:
    - Header validation (typ, jwk presence, asymmetric key, key strength)
    - Signature verification (with the algorithm allowlist pinned)
    - Claim type validation (iat, exp, jti, htm, htu, nonce)
    - Time-based validation (iat, exp)
    - htm (HTTP method) validation
    - htu (URL) validation
    - ath (access token hash) validation if provided
    - nonce validation if required
    - jti replay rejection if jti_seen_callback is provided

    Args:
        dpop_header (str): The DPoP proof JWT string from the DPoP header.
        request_method (str): The HTTP method of the incoming request.
        request_url (str): The full URL of the incoming request (scheme + host +
            path), as the CLIENT saw it.
        unvalidated_access_token (str | None): Optional access token to validate ath claim against.
        require_nonce (bool): Whether to require and validate a nonce.
        secret (str | None): Optional secret key for stateless nonce verification.
            If None, defaults to the environment-configured secret.
        as_resource_server (bool): Default True. Whether caller is a Resource Server.
            False implies caller is the Authorization Server. This alters some of the
            error messaging behavior (per the spec).
        jti_seen_callback (Callable | None): a callback taking (jti: str) that
            returns True if this jti has already been used, per RFC 9449 11.1.

    Returns:
        dict[str, Any], jwk.Key: dict with decoded claims dict, validated client_jwk from dpop header

    Raises:
        ValueError: If any validation fails. All underlying JoseError,
            TypeError and UnicodeEncodeError failures are normalized to
            ValueError so that callers can rely on a single exception type.
        InvalidNonceError: If nonce is missing or invalid. This will contain the error,
            description, and a valid nonce for the caller to send back to client as
            header (per spec). Caller must extract the information from this exception.

    Example:
        >>> claims = validate_dpop_proof(
        ...     dpop_header="eyJ0eXAi...",
        ...     request_method="GET",
        ...     request_url="https://api.example.com/ga4gh/tes/v1/jobs",
        ... )
    """
    if not dpop_header:
        raise ValueError("Invalid DPoP proof: Empty string / None provided")

    if not isinstance(dpop_header, str):
        raise ValueError(
            f"Invalid DPoP proof: expected a string, got {type(dpop_header).__name__}"
        )

    if len(dpop_header) > MAX_DPOP_HEADER_LENGTH:
        raise ValueError(
            f"Invalid DPoP proof: header exceeds {MAX_DPOP_HEADER_LENGTH} characters"
        )

    # get rid of any prefixed 'DPoP ' / 'dpop '
    dpop_header = _strip_auth_scheme(dpop_header)

    client_jwk = extract_and_validate_jwk(dpop_header)

    dpop_claims = _verify_signature_and_claims(dpop_header, client_jwk)

    _validate_proof_claims(dpop_claims, request_method, request_url)

    if require_nonce or "nonce" in dpop_claims:
        _validate_nonce(
            dpop_claims,
            require_nonce=require_nonce,
            secret=secret,
            as_resource_server=as_resource_server,
        )

    if jti_seen_callback is not None:
        if jti_seen_callback(dpop_claims["jti"]):
            raise ValueError(
                "DPoP proof replay detected: jti has already been used "
                "within its validity window"
            )

    if unvalidated_access_token:
        _reject_bearer_prefixed_token(unvalidated_access_token)
        _validate_ath(dpop_claims, unvalidated_access_token)
        _validate_key_binding(client_jwk, unvalidated_access_token)

    return dpop_claims, client_jwk


def extract_and_validate_jwk(dpop_header: str) -> jwk.Key:
    """
    Extract and validate embedded JWK from DPoP proof header.

    Args:
        dpop_header (str): Raw DPoP JWT string.

    Returns:
        jwk.Key: Validated asymmetric jwk.Key.

    Raises:
        ValueError: If header is malformed, missing jwk, uses a symmetric key,
            uses a disallowed algorithm/curve, or the key is undersized.
    """
    # get rid of any prefixed 'DPoP ' / 'dpop '
    dpop_header = _strip_auth_scheme(dpop_header)

    # Use custom registry with increased header size limit for DPoP proofs
    # containing full JWKs (especially RSA keys which have large public keys).
    registry = _new_registry()

    try:
        # extract_compact only PARSES - it does not enforce the algorithm
        # allowlist. The explicit SUPPORTED_DPOP_ALGS check below
        # actually constrains the algorithm.
        unverified_header: dict = jws.extract_compact(
            dpop_header.encode("utf-8"), registry=registry
        ).protected
    except Exception as exc:
        logging.error(exc, exc_info=True, stack_info=True)
        raise ValueError("Invalid DPoP proof: malformed compact JWS structure")

    alg = unverified_header.get("alg")
    if alg not in SUPPORTED_DPOP_ALGS:
        raise ValueError(f"Unsupported or unpermitted DPoP signature algorithm: {alg}")

    typ = unverified_header.get("typ")
    if not isinstance(typ, str) or typ.lower() != DPOP_JWT_TYPE:
        raise ValueError(f"DPoP proof must have typ '{DPOP_JWT_TYPE}'")

    if "jwk" not in unverified_header:
        raise ValueError("DPoP proof header must contain 'jwk'")

    if not isinstance(unverified_header["jwk"], dict):
        raise ValueError("DPoP proof header 'jwk' must be a JSON object")

    try:
        client_jwk: jwk.Key = jwk.import_key(unverified_header["jwk"])
    except Exception as exc:
        logging.error(exc, exc_info=True, stack_info=True)
        raise ValueError("Invalid DPoP proof: embedded jwk could not be imported")

    # Check if key is symmetric (oct/HMAC)
    # joserfc exposes the key type as `key_type`, not `kty`. Read it defensively
    # anyway: an unreadable or unexpected type falls into the reject branch
    # below rather than being treated as asymmetric by default.
    key_type = str(getattr(client_jwk, "key_type", "") or "").lower()

    if not key_type or key_type in ("none", "oct", "symmetric", "hmac"):
        raise ValueError(f"DPoP proof must use asymmetric key. Got: `{key_type}`")

    if hasattr(client_jwk, "is_private") and client_jwk.is_private:
        raise ValueError("DPoP proof jwk must not contain a private key")

    _validate_key_strength(client_jwk, key_type)

    return client_jwk


def compute_ath(access_token: str | bytes) -> str:
    """
    Compute base64url(SHA-256(token)) per RFC 9449 4.2.

    "ath: Hash of the access token. The value MUST be the result
    of a base64url encoding (as defined in Section 2 of [RFC7515])
    the SHA-256 [SHS] hash of the ASCII encoding of the associated
    access token's value."

    Args:
        access_token (str | bytes): The access token (can be string or bytes).

    Returns:
        str: Base64url-encoded SHA-256 hash.

    Raises:
        TypeError: If access_token is neither str nor bytes.
        UnicodeEncodeError: If a str token contains non-ASCII characters, per
            RFC 9449 4.2's requirement to hash the ASCII encoding.
    """
    if isinstance(access_token, str):
        token_bytes = access_token.encode("ascii")
    elif isinstance(access_token, bytes):
        token_bytes = access_token
    else:
        raise TypeError(
            f"access_token must be str or bytes, not {type(access_token).__name__}"
        )

    digest = hashlib.sha256(token_bytes).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class _LargeHeaderRegistry(jws.JWSRegistry):
    """
    JWS registry for DPoP proofs: larger header limit, mandatory alg pinning.

    Two deviations from the joserfc base class, both deliberate:

    - `max_header_length` is raised, because a DPoP proof embeds the full
      public JWK in its header and RSA keys exceed the default limit.
    - `algorithms` is REQUIRED and must be non-empty. joserfc's `get_alg`
      guards with `if self.allowed:`, so a falsy collection (`None`,
      `set()`, `[]`) silently falls through to "allow every recommended
      algorithm" - which includes symetric algs not allowed.
    """

    max_header_length = 4096

    def __init__(
        self,
        header_registry: dict | None = None,
        algorithms: Collection[str] | None = None,
        strict_check_header: bool = True,
    ) -> None:
        """
        Build the registry, refusing any falsy algorithm allowlist.

        Args:
            header_registry (dict | None): Extra JOSE header definitions.
            algorithms (Collection[str] | None): Permitted JWS algorithms. Required.
            strict_check_header (bool): Whether to reject unknown header params.

        Raises:
            ValueError: If algorithms is empty or None.
        """
        if not algorithms:
            raise ValueError(
                "A non-empty 'algorithms' allowlist is required. joserfc treats a "
                "falsy algorithms collection as 'allow all recommended algorithms', "
                "which would permit disallowed DPoP algorithms."
            )
        super().__init__(
            header_registry=header_registry,
            algorithms=algorithms,
            strict_check_header=strict_check_header,
        )


def _new_registry() -> _LargeHeaderRegistry:
    """
    Build a JWS registry with the DPoP algorithm allowlist pinned.

    Returns:
        _LargeHeaderRegistry: Registry pinned to SUPPORTED_DPOP_ALGS.

    Raises:
        ValueError: If SUPPORTED_DPOP_ALGS has been reassigned to a falsy
            value, which would otherwise silently disable checks.
    """
    return _LargeHeaderRegistry(algorithms=SUPPORTED_DPOP_ALGS)


def _strip_auth_scheme(header_value: str, expected_scheme: str = "dpop") -> str:
    """
    Strip an optional auth scheme prefix (e.g. "DPoP <proof>") from a header.

    Rejects a mismatched scheme rather than silently accepting it, so that a
    value copied out of the wrong header (e.g. "Bearer eyJ...") fails loudly.

    Args:
        header_value (str): Raw header value.
        expected_scheme (str): Scheme to permit, compared case-insensitively.

    Returns:
        str: The header value with any scheme prefix removed.

    Raises:
        ValueError: If a scheme prefix is present but is not expected_scheme.
    """
    stripped = header_value.strip()
    if " " not in stripped:
        return stripped

    scheme, _, remainder = stripped.partition(" ")
    remainder = remainder.strip()

    # A JWT has no spaces, so a leading token containing no '.' is a scheme.
    if "." not in scheme:
        if scheme.lower() != expected_scheme.lower():
            raise ValueError(
                f"Invalid DPoP proof: unexpected authorization scheme '{scheme}'. "
                f"Expected '{expected_scheme}' or a bare JWT."
            )
        return remainder

    raise ValueError("Invalid DPoP proof: contains unexpected whitespace")


def _reject_bearer_prefixed_token(access_token: str) -> str:
    """
    Reject an access token that still carries the 'Bearer ' prefix.

    The ath claim is computed over the raw token, so a full Authorization
    header value would silently produce an ath mismatch (or a JSON parse
    failure when reading cnf.jkt). Fail with a clear message instead.

    Args:
        access_token (str): The access token as supplied by the caller.

    Returns:
        str: The access token unchanged.

    Raises:
        ValueError: If the value is prefixed with an auth scheme.
    """
    if not isinstance(access_token, str):
        raise ValueError(
            f"access_token must be a string, not {type(access_token).__name__}"
        )

    lowered = access_token.lower()
    for scheme in ("bearer ", "dpop "):
        if lowered.startswith(scheme):
            raise ValueError(
                f"The provided access_token contains the '{scheme.strip()} ' prefix. "
                "DPoP ath and cnf.jkt checks must use only the raw JWT/access token. "
                "Ensure you are not passing an Authorization header's full contents."
            )
    return access_token


def _resolve_proof_alg(key: jwk.Key) -> str:
    """
    Pick the correct JWS algorithm for a DPoP proof signing key.

    Args:
        key (jwk.Key): The proof signing key.

    Returns:
        str: The JWS "alg" value to use.

    Raises:
        ValueError: If the key type or curve is not supported for DPoP.
    """
    key_type = (getattr(key, "kty", "") or getattr(key, "key_type", "")).upper()

    if key_type == "RSA":
        return "RS256"

    if key_type == "EC":
        crv = key.as_dict(private=False).get("crv")
        if crv not in EC_CURVE_TO_ALG:
            raise ValueError(
                f"Unsupported EC curve for DPoP proof: {crv}. "
                f"Allowed: {sorted(ALLOWED_EC_CURVES)}"
            )
        return EC_CURVE_TO_ALG[crv]

    raise ValueError(
        f"Unsupported key type for DPoP proof: '{key_type}'. "
        "DPoP requires an asymmetric EC or RSA key."
    )


def _validate_key_strength(client_jwk: jwk.Key, key_type: str) -> None:
    """
    Reject proof keys that are too weak or use a disallowed curve.

    joserfc only warns for RSA moduli below 2048 bits, and does not restrict
    EC curves. A DPoP proof key is bound into issued access tokens via
    cnf.jkt, so a weak key weakens every token bound to it.

    Args:
        client_jwk (jwk.Key): The public key from the DPoP proof header.
        key_type (str): Lowercased key type ("rsa" or "ec").

    Raises:
        ValueError: If the key is undersized or uses a disallowed curve.
    """
    key_dict = client_jwk.as_dict(private=False)

    if key_type == "rsa":
        # The modulus is known-decodable here: jwk.import_key decodes n to
        # build the key and raises before this point if it cannot.
        modulus = str(key_dict.get("n", ""))
        padding = "=" * (-len(modulus) % 4)
        modulus_bits = len(base64.urlsafe_b64decode(modulus + padding)) * 8
        if modulus_bits < MIN_RSA_KEY_BITS:
            raise ValueError(
                f"DPoP proof RSA key is too small: {modulus_bits} bits "
                f"(minimum {MIN_RSA_KEY_BITS})"
            )

    elif key_type == "ec":
        crv = key_dict.get("crv")
        if crv not in ALLOWED_EC_CURVES:
            raise ValueError(
                f"DPoP proof uses a disallowed EC curve: {crv}. "
                f"Allowed: {sorted(ALLOWED_EC_CURVES)}"
            )


def _validate_key_binding(
    client_jwk: jwk.Key,
    access_token: str,
) -> None:
    """
    Validate that a client's public key matches a token's cnf.jkt claim.

    Args:
        client_jwk (jwk.Key): The public key from the DPoP proof header.
        access_token (str): The JWT access token string.

    Raises:
        ValueError: If binding validation fails.
    """
    token_jkt = _get_token_jkt(access_token)
    proof_thumbprint = client_jwk.thumbprint()

    if proof_thumbprint != token_jkt:
        raise ValueError(
            f"Key binding mismatch: proof thumbprint '{proof_thumbprint}' "
            f"doesn't match token cnf.jkt '{token_jkt}'"
        )


def _validate_claim_types(claims_dict: dict[str, Any]) -> None:
    """
    Enforce claim types before any arithmetic or string comparison.

    Without this, a proof carrying e.g. {"iat": "9999999999"} reaches the
    freshness arithmetic and raises an uncaught TypeError.

    Args:
        claims_dict (dict[str, Any]): Decoded DPoP proof claims.

    Raises:
        ValueError: If any present claim has an unexpected type.
    """
    for numeric_claim in ("iat", "exp", "nbf"):
        if numeric_claim in claims_dict:
            value = claims_dict[numeric_claim]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"DPoP proof '{numeric_claim}' claim must be a number, "
                    f"got {type(value).__name__}"
                )

    for string_claim in ("jti", "htm", "htu", "nonce", "ath"):
        if string_claim in claims_dict and not isinstance(
            claims_dict[string_claim], str
        ):
            raise ValueError(
                f"DPoP proof '{string_claim}' claim must be a string, "
                f"got {type(claims_dict[string_claim]).__name__}"
            )


def _verify_signature_and_claims(
    dpop_header: str, client_jwk: jwk.Key
) -> dict[str, Any]:
    """
    Verify JWS signature and decode claims with leeway.

    Args:
        dpop_header (str): Raw DPoP JWT string.
        client_jwk (jwk.Key): Public key extracted from the proof header.

    Returns:
        dict[str, Any]: Decoded claims dict.

    Raises:
        ValueError: If signature verification, claim typing, or time
            validation fails. joserfc's JoseError subclasses are normalized to
            ValueError here so callers see a single exception type.
    """
    registry = _new_registry()

    try:
        dpop_claims = jwt.decode(dpop_header, client_jwk, registry=registry)
    except JoseError as exc:
        logging.error(exc, exc_info=True, stack_info=True)
        raise ValueError(f"Invalid DPoP proof: {exc}")
    except Exception as exc:
        logging.error(exc, exc_info=True, stack_info=True)
        raise ValueError("Invalid DPoP proof: could not verify signature")

    claims_dict = dpop_claims.claims

    if not isinstance(claims_dict, dict):
        raise ValueError("Invalid DPoP proof: payload is not a JSON object")

    _validate_claim_types(claims_dict)

    current_time = int(time.time())

    if "exp" in claims_dict:
        if current_time >= claims_dict["exp"]:
            raise ValueError("Invalid DPoP proof: expired")

    # Check iat (issued at) - not too old (5 min leeway like authlib)
    # The proof should be generated moments before the request is sent
    if "iat" in claims_dict:
        # Reject if proof is older than DPOP_PROOF_MAX_TTL
        if claims_dict["iat"] + DPOP_PROOF_MAX_TTL < current_time:
            raise ValueError("Invalid DPoP proof: proof created too far in the past")

        # Reject if proof is issued in the future (allowing minor clock skew)
        if claims_dict["iat"] - DPOP_PROOF_CLOCK_SKEW_LEEWAY > current_time:
            raise ValueError("Invalid DPoP proof: proof issued in the future")

    return claims_dict


def _validate_proof_claims(
    dpop_claims: dict[str, Any], request_method: str, request_url: str
) -> None:
    """
    Validate required claims for a DPoP proof on a resource request.

    Args:
        dpop_claims (dict[str, Any]): Decoded DPoP proof claims.
        request_method (str): The HTTP method of the incoming request.
        request_url (str): The full URL of the incoming request.

    Raises:
        ValueError: If any claim is missing or mismatched.
    """
    jti = dpop_claims.get("jti")
    if not jti:
        raise ValueError("DPoP proof missing jti")

    if "iat" not in dpop_claims:
        raise ValueError("DPoP proof missing required 'iat' claim")

    # protect against arbitrarily large jti's
    if not isinstance(jti, str) or len(jti) > MAX_JTI_LENGTH:
        raise ValueError("DPoP proof jti is malformed or unnecessarily large")

    if not isinstance(request_method, str) or not request_method:
        raise ValueError("request_method must be a non-empty string")

    # Treat a missing URL as a caller bug rather than comparing.
    if not isinstance(request_url, str) or not request_url:
        raise ValueError("request_url must be a non-empty string")

    htm_value = dpop_claims.get("htm", "")
    if request_method.upper() != htm_value.upper():
        raise ValueError(
            f"htm mismatch: expected '{request_method}', htm in proof: '{htm_value}'"
        )

    htu_value = dpop_claims.get("htu", "")

    # RFC 9449 4.2 requires htu to carry no query or fragment. Reject rather
    # than normalize, so a non-compliant proof cannot be silently accepted.
    if "?" in htu_value or "#" in htu_value:
        raise ValueError(
            "DPoP proof 'htu' claim must not contain a query string or fragment"
        )

    # Normalize BOTH sides so that an explicit default port (e.g. :443 added by
    # a reverse proxy) does not cause a mismatch.
    actual_url = _get_url(request_url)
    if actual_url != _get_url(htu_value):
        raise ValueError(
            f"htu mismatch: request URL '{actual_url}' != proof htu '{htu_value}'"
        )


def _validate_nonce(
    dpop_claims: dict[str, Any],
    require_nonce: bool,
    secret: str | None = None,
    as_resource_server: bool = True,
) -> None:
    """
    Validate DPoP nonce; raise InvalidNonceError if missing or expired.
    InvalidNonceError will CONTAIN the new nonce and error response information
    required per the spec.

    Args:
        dpop_claims (dict[str, Any]): Decoded DPoP proof claims.
        require_nonce (bool): Whether a nonce is required. If True and no nonce
            is present, raises InvalidNonceError. If False and no nonce is present,
            the function returns early without validation.
        secret (str | None): Optional secret key for stateless nonce verification.
            If None, defaults to the environment-configured secret.
        as_resource_server (bool): Whether the caller is a Resource Server,
            which determines the error class and HTTP status used.

    Raises:
        InvalidNonceError: If nonce is missing when required, or if the nonce is
            invalid or expired according to verify_stateless_nonce.
    """
    client_nonce = dpop_claims.get("nonce", "")

    if not client_nonce:
        if require_nonce:
            _raise_invalid_nonce(as_resource_server, secret)

        # Nonce wasn't required and wasn't provided, safe to skip
        return

    if not verify_stateless_nonce(client_nonce, secret=secret):
        _raise_invalid_nonce(as_resource_server, secret)


def _raise_invalid_nonce(as_resource_server: bool, secret: str | None) -> None:
    """Raises appropriate error based on whether the caller is a Resource Server."""
    if as_resource_server:
        raise InvalidNonceErrorResourceServer(
            new_nonce=generate_stateless_nonce(secret=secret)
        )
    raise InvalidNonceErrorAuthorizationServer(
        new_nonce=generate_stateless_nonce(secret=secret)
    )


def _validate_ath(dpop_claims: dict[str, Any], access_token: str) -> None:
    """
    Validate access token hash per RFC 9449 4.2.

    Args:
        dpop_claims (dict[str, Any]): Decoded DPoP proof claims.
        access_token (str): The access token string.

    Raises:
        ValueError: If ath is absent, or does not match SHA-256 of the token.
    """
    if "ath" not in dpop_claims:
        raise ValueError(
            "DPoP proof is missing the 'ath' claim, which is required when "
            "presented alongside an access token (RFC 9449 4.2)"
        )

    try:
        expected_ath = compute_ath(access_token)
    except (UnicodeEncodeError, TypeError) as exc:
        raise ValueError(f"Could not compute ath for the provided access token: {exc}")

    if dpop_claims.get("ath") != expected_ath:
        # Deliberately does not include the token or its expected hash.
        raise ValueError("ath claim does not match the presented access token")


def _get_token_jkt(access_token: str) -> str:
    """
    Extract the jkt (key thumbprint) from a token's cnf claim.

    Args:
        access_token (str): The JWT access token string.

    Returns:
        str: The key thumbprint string.

    Raises:
        ValueError: If the token is malformed or the jkt claim is missing/invalid.
    """
    claims = _get_unverified_claims(access_token)
    cnf = claims.get("cnf", {})

    if not isinstance(cnf, dict):
        raise ValueError("Access token cnf claim must be an object")

    jkt = cnf.get("jkt")

    # Validate jkt is a non-empty string (reject null, array, empty string)
    if not isinstance(jkt, str) or not jkt:
        raise ValueError("Access token cnf.jkt must be a non-empty string")

    return jkt


def _get_url(url: str) -> str:
    """
    Extract the scheme, host, and path from a URL for the DPoP htu claim.

    Strips out query strings and fragments per RFC 9449 Section 4.2, and
    removes a scheme's default port so that 'https://x/y' and
    'https://x:443/y' compare equal (RFC 9110 4.2).

    Args:
        url (str): The full request URL.

    Returns:
        str: The sanitized HTTP target URI (e.g., 'https://example.com/api/v1/resource')
    """
    if not url:
        logging.warning(
            "No URL provided for DPoP htu claim. Using empty string instead."
        )
        return ""

    # urlsplit, not urlparse: urlparse peels ";params" off the last path
    # segment into a separate field, so rebuilding from .path alone would
    # silently drop it - making a proof minted for "/a" also satisfy a request
    # to "/a;evil", which weakens the request binding htu exists to provide.
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()

    # Drop an explicit default port so proxy-added ':443' does not break htu
    # comparison.
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(f"URL contains an invalid port: {url}")

    hostname = (parsed.hostname or "").lower()
    netloc = hostname
    if port is not None and str(port) != DEFAULT_PORTS_BY_SCHEME.get(scheme):
        netloc = f"{hostname}:{port}"

    # Rebuild using only scheme, netloc (host/port), and path.
    # This automatically drops parsed.query and parsed.fragment.
    return f"{scheme}://{netloc}{parsed.path}"


def _get_unverified_claims(token: str) -> dict[str, Any]:
    """
    Extract the JWT claims payload WITHOUT verifying the signature.

    IMPORTANT: Verify the signature elsewhere!

    Args:
        token (str): The encoded JWT.

    Returns:
        dict[str, Any]: The decoded claims payload.

    Raises:
        ValueError: If the token is not a well-formed JWS with a JSON payload.
    """
    if not isinstance(token, str) or not token:
        raise ValueError("Cannot read claims: token must be a non-empty string")

    try:
        token_bytes = token.encode("utf-8")

        # (header, payload, signature)
        obj = jws.extract_compact(token_bytes)

        # The payload is returned as bytes, so we decode and parse the JSON
        claims = json.loads(obj.payload.decode("utf-8"))
    except Exception as exc:
        logging.error(exc, exc_info=True, stack_info=True)
        raise ValueError("Could not read claims: token is not a well-formed JWT")

    if not isinstance(claims, dict):
        raise ValueError("Could not read claims: token payload is not a JSON object")

    return claims
