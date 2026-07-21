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
from typing import Callable, Dict, Any, Tuple
from urllib.parse import urlparse

from joserfc import jwt, jwk, jws
from joserfc.errors import JoseError

from authutils.token.dpop_nonce import verify_stateless_nonce
from authutils.token import core as token_core
from authutils.token.keys import get_any_public_key_for_token

DPOP_JWT_TYPE = "dpop+jwt"
DEFAULT_DPOP_ALGORITHM = "ES256"
SUPPORTED_DPOP_ALGS = {
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

# will invalidate any proof older than 5 minutes
DPOP_PROOF_MAX_TTL = 300

# will invalidate any proof created more than 60 seconds into the future
# this provides some leeway for clock skewing across client / server
DPOP_PROOF_CLOCK_SKEW_LEEWAY = 60

# to avoid unnecessarilly large JTIs since we may
# want to cache these in the future
MAX_JTI_LENGTH = 256


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

    Returns:
        str: Encoded DPoP proof JWT string.

    Example:
        >>> key = jwk.generate_key("EC", "P-256", private=True)
        >>> proof = generate_dpop_proof(
        ...     key,
        ...     "POST",
        ...     "https://fence.example.com/credentials/api/access_token",
        ... )
    """
    if not alg:
        key_type = (getattr(key, "kty", "") or getattr(key, "key_type", "")).upper()
        if key_type == "RSA":
            alg = "RS256"
        elif key_type == "EC":
            alg = "ES256"
        else:
            alg = DEFAULT_DPOP_ALGORITHM

    header = {
        "typ": DPOP_JWT_TYPE,
        "alg": alg,
        "jwk": key.as_dict(private=False),
    }
    payload: Dict[str, Any] = {
        "jti": os.urandom(16).hex(),
        "htm": method.upper(),
        "htu": _get_url(url),
        "iat": int(time.time()),
    }

    if access_token:
        payload["ath"] = _compute_ath(access_token)

    if nonce:
        payload["nonce"] = nonce

    return jwt.encode(header, payload, key)


def validate_dpop_request(
    dpop_header: str,
    access_token: str,
    request_method: str,
    request_url: str,
    issuers: list[str],
    public_key: str | None = None,
    scope: set[str] | list[str] | None = None,
    purpose: str | None = None,
    aud: str | None = None,
    require_nonce: bool = False,
    options: dict | None = None,
    denylist_callback: Callable | None = None,
) -> Dict[str, Any]:
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
        request_url (str): The full URL of the incoming request (scheme + host + path).
        issuers (list[str]): Allowed token issuers whitelist.
        public_key (str | None): Optional public key for token validation. If None, will be
            fetched from the token issuer's JWKS endpoint.
        scope (set[str] | list[str] | None): Optional required scopes that the token must satisfy.
        purpose (str | None): Optional required purpose (e.g., "access"). Must match token's pur claim.
        aud (str | None): Optional audience. Note: authutils no longer validates audience.
        require_nonce (bool): Whether to require and validate a DPoP nonce.
        options (dict | None): options to pass through to pyjwt's decode
        denylist_callback (Callable | None): a callback function that takes
          (jti: str) and returns True if the token is denylisted.
          The callback is called after basic JWT validation.

    Returns:
        Dict[str, Any]: The validated access token claims dict.

    Raises:
        ValueError: If DPoP proof validation fails.
        JWTError: If access token validation fails (signature, expiration, issuer, scope, purpose).
    """
    validate_dpop_proof(
        dpop_header=dpop_header,
        request_method=request_method,
        request_url=request_url,
        unvalidated_access_token=access_token,
        require_nonce=require_nonce,
    )

    if public_key is None:
        # Fetch public key from issuer's JWKS endpoint if not provided
        public_key = get_any_public_key_for_token(access_token)

    # Normalize scope to list/set for validation
    if isinstance(scope, list):
        scope = set(scope)

    validated_claims = token_core.validate_jwt(
        encoded_token=access_token,
        public_key=public_key,
        aud=aud,
        scope=scope,
        allowed_issuers=issuers,
        purpose=purpose,
        options=options,
        denylist_callback=denylist_callback,
    )

    return validated_claims


def validate_dpop_proof(
    dpop_header: str,
    request_method: str,
    request_url: str,
    unvalidated_access_token: str | None = None,
    require_nonce: bool = False,
) -> Tuple[Dict[str, Any], jwk.Key]:
    """
    Validate a DPoP proof JWT for a resource server request.

    IMPORTANT: This DOES NOT validate the unvalidated_access_token beyond the validation
               of it being bound to the DPoP Proof. e.g. you MUST separately
               validate the access token and any additional authorization.

    This function performs comprehensive validation of a DPoP proof including:
    - Header validation (typ, jwk presence, asymmetric key)
    - Signature verification
    - Time-based validation (iat, exp)
    - htm (HTTP method) validation
    - htu (URL) validation
    - ath (access token hash) validation if provided
    - nonce validation if required

    Args:
        dpop_header (str): The DPoP proof JWT string from the DPoP header.
        request_method (str): The HTTP method of the incoming request.
        request_url (str): The full URL of the incoming request (scheme + host + path).
        unvalidated_access_token (str | None): Optional access token to validate ath claim against.
        require_nonce (bool): Whether to require and validate a nonce.

    Returns:
        Dict[str, Any], jwk.Key: dict with decoded claims dict, validated client_jwk from dpop header

    Raises:
        ValueError: If any validation fails.

    Example:
        >>> claims = validate_dpop_proof(
        ...     dpop_header="eyJ0eXAi...",
        ...     request_method="GET",
        ...     request_url="https://api.example.com/ga4gh/tes/v1/jobs",
        ... )
    """
    if not dpop_header:
        raise ValueError("Invalid DPoP proof: Empty string / None provided")

    client_jwk = extract_and_validate_jwk(dpop_header)

    dpop_claims = _verify_signature_and_claims(dpop_header, client_jwk)

    _validate_proof_claims(dpop_claims, request_method, request_url)

    if require_nonce or "nonce" in dpop_claims:
        _validate_nonce_or_reject(dpop_claims, require_nonce=require_nonce)

    if unvalidated_access_token:
        _validate_ath(dpop_claims, unvalidated_access_token)
        _validate_key_binding(client_jwk, unvalidated_access_token)

    return dpop_claims, client_jwk


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


def extract_and_validate_jwk(dpop_header: str) -> jwk.Key:
    """
    Extract and validate embedded JWK from DPoP proof header.

    Args:
        dpop_header (str): Raw DPoP JWT string.

    Returns:
        jwk.Key: Validated asymmetric jwk.Key.

    Raises:
        ValueError: If header is malformed, missing jwk, or uses symmetric key.
    """
    try:
        unverified_header: dict = jws.extract_compact(
            dpop_header.encode("utf-8")
        ).protected
    except Exception:
        raise ValueError("Invalid DPoP proof: malformed compact JWS structure")

    alg = unverified_header.get("alg")
    if alg not in SUPPORTED_DPOP_ALGS:
        raise ValueError(f"Unsupported or unpermitted DPoP signature algorithm: {alg}")

    if unverified_header.get("typ", "").lower() != DPOP_JWT_TYPE:
        raise ValueError(f"DPoP proof must have typ '{DPOP_JWT_TYPE}'")

    if "jwk" not in unverified_header:
        raise ValueError("DPoP proof header must contain 'jwk'")

    client_jwk: jwk.Key = jwk.import_key(unverified_header["jwk"])

    # Check if key is symmetric (oct/HMAC)
    # joserfc keys have kty attribute, but if checking fails, check key_type
    try:
        key_type = getattr(client_jwk, "kty", "") or getattr(client_jwk, "key_type", "")
        key_type = key_type.lower()
    except Exception:
        key_type = None

    if not key_type or key_type in ("none", "oct", "symmetric", "hmac"):
        raise ValueError(f"DPoP proof must use asymmetric key. Got: `{key_type}`")

    if hasattr(client_jwk, "is_private") and client_jwk.is_private:
        raise ValueError("DPoP proof jwk must not contain a private key")

    return client_jwk


def _verify_signature_and_claims(
    dpop_header: str, client_jwk: jwk.Key
) -> Dict[str, Any]:
    """
    Verify JWS signature and decode claims with leeway.

    Args:
        dpop_header (str): Raw DPoP JWT string.
        client_jwk (jwk.Key): Public key extracted from the proof header.

    Returns:
        Dict[str, Any]: Decoded claims dict.

    Raises:
        JoseError: If signature verification or time validation fails.
    """
    dpop_claims = jwt.decode(dpop_header, client_jwk)

    claims_dict = dpop_claims.claims
    current_time = int(time.time())

    if "exp" in claims_dict:
        if current_time >= claims_dict["exp"]:
            raise JoseError("Invalid token: expired")

    # Check iat (issued at) - not too old (5 min leeway like authlib)
    # The proof should be generated moments before the request is sent
    if "iat" in claims_dict:
        # Reject if proof is older than
        if claims_dict["iat"] + DPOP_PROOF_MAX_TTL < current_time:
            raise JoseError("Invalid token: proof created too far in the past")

        # Reject if proof is issued in the future (allowing minor clock skew)
        if claims_dict["iat"] - DPOP_PROOF_CLOCK_SKEW_LEEWAY > current_time:
            raise JoseError("Invalid token: proof issued in the future")

    return claims_dict


def _validate_proof_claims(
    dpop_claims: Dict[str, Any], request_method: str, request_url: str
) -> None:
    """
    Validate required claims for a DPoP proof on a resource request.

    Args:
        dpop_claims (Dict[str, Any]): Decoded DPoP proof claims.
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

    htm_value: str = dpop_claims.get("htm", "")
    if request_method.upper() != htm_value.upper():
        raise ValueError(
            f"htm mismatch: expected '{request_method}', htm in proof: '{htm_value}'"
        )

    htu_value: str = dpop_claims.get("htu", "")
    actual_url: str = _get_url(request_url)
    if actual_url != htu_value:
        raise ValueError(
            f"htu mismatch: request URL '{actual_url}' != proof htu '{htu_value}'"
        )


def _validate_nonce_or_reject(dpop_claims: Dict[str, Any], require_nonce: bool) -> None:
    """
    Validate nonce; raise ValueError if missing or expired.

    Args:
        dpop_claims (Dict[str, Any]): Decoded DPoP proof claims.

    Raises:
        ValueError: If nonce is missing or expired.
    """
    client_nonce: str = dpop_claims.get("nonce", "")

    if not client_nonce:
        if require_nonce:
            raise ValueError("DPoP proof missing required server nonce")

        # Nonce wasn't required and wasn't provided, safe to skip
        return

    if not verify_stateless_nonce(client_nonce):
        raise ValueError("Invalid or expired DPoP nonce")


def _validate_ath(dpop_claims: Dict[str, Any], access_token: str) -> None:
    """
    Validate access token hash per RFC 9449 §4.2.

    Args:
        dpop_claims (Dict[str, Any]): Decoded DPoP proof claims.
        access_token (str): The access token string.

    Raises:
        ValueError: If ath does not match SHA-256 of the token.
    """
    expected_ath: str = _compute_ath(access_token)
    if dpop_claims.get("ath") != expected_ath:
        raise ValueError("ath claim does not match access token hash")


def _compute_ath(access_token: str | bytes) -> str:
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


def _get_token_jkt(access_token: str) -> str:
    """
    Extract the jkt (key thumbprint) from a token's cnf claim.

    Args:
        access_token (str): The JWT access token string.

    Returns:
        str: The key thumbprint string.

    Raises:
        ValueError: If jkt claim is missing or invalid.
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
    Strips out query strings and fragments per RFC 9449 Section 4.2.

    Args:
        url (str): The full request URL.

    Returns:
        str: The sanitized HTTP target URI (e.g., 'https://example.com/api/v1/resource')
    """
    parsed = urlparse(url)

    # Rebuild the URL using only scheme, netloc (host/port), and path
    # This automatically drops parsed.query and parsed.fragment
    clean_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"

    return clean_url


def _get_unverified_claims(token: str) -> Dict[str, Any]:
    """
    Extract the JWT claims payload WITHOUT verifying the signature.

    IMPORTANT: Verify the signature elsewhere!
    """
    token_bytes = token.encode("utf-8")

    # (header, payload, signature)
    obj = jws.extract_compact(token_bytes)

    # The payload is returned as bytes, so we decode and parse the JSON
    claims = json.loads(obj.payload.decode("utf-8"))

    return claims
