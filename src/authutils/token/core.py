import httpx2
import jwt
from collections.abc import Callable

from jwt.types import Options

from ..errors import (
    JWTAudienceError,
    JWTExpiredError,
    JWTPurposeError,
    JWTScopeError,
    JWTError,
)

from cdislogging import get_logger

logging = get_logger(__name__)

# Timeout for each outbound key-discovery request.
# NOTE: the discovery doc here and the JWKS fetch in token.keys both use
# it, so a cold lookup can take 2x this.
KEYS_REQUEST_TIMEOUT = 10.0


def get_keys_url(issuer, force_issuer=None):
    """
    Prefer OIDC discovery doc, but fall back on Fence-specific /jwt/keys for backwards compatibility (or if `force_issuer` is True)
    """
    jwt_keys_url, openid_cfg_path = _keys_url_candidates(issuer, force_issuer)
    if openid_cfg_path is None:
        return jwt_keys_url

    try:
        jwks_uri = (
            httpx2.get(
                openid_cfg_path, timeout=httpx2.Timeout(timeout=KEYS_REQUEST_TIMEOUT)
            )
            .json()
            .get("jwks_uri", "")
        )
        return jwks_uri
    except Exception as exc:
        _log_discovery_fallback(openid_cfg_path, jwt_keys_url, exc)
        return jwt_keys_url


async def get_keys_url_async(issuer: str, force_issuer: bool | None = None) -> str:
    """
    Async counterpart of get_keys_url.

    Same discovery-then-fallback behavior; issues the OIDC discovery request
    on an AsyncClient so an async caller does not block its event loop.

    Args:
        issuer (str): The token issuer.
        force_issuer (bool | None): Skip discovery and use /jwt/keys.

    Returns:
        str: The keys URL to fetch.
    """
    jwt_keys_url, openid_cfg_path = _keys_url_candidates(issuer, force_issuer)
    if openid_cfg_path is None:
        return jwt_keys_url

    try:
        async with httpx2.AsyncClient() as client:
            response = await client.get(
                openid_cfg_path, timeout=httpx2.Timeout(timeout=KEYS_REQUEST_TIMEOUT)
            )
        return response.json().get("jwks_uri", "")
    except Exception as exc:
        _log_discovery_fallback(openid_cfg_path, jwt_keys_url, exc)
        return jwt_keys_url


def get_kid(encoded_token):
    try:
        return jwt.get_unverified_header(encoded_token).get("kid")
    except jwt.InvalidTokenError as e:
        raise JWTError(e)


def get_iss(encoded_token):
    try:
        return jwt.decode(
            encoded_token, options={"verify_signature": False, "verify_exp": True}
        ).get("iss")
    except jwt.InvalidTokenError as e:
        raise JWTError(e)


def validate_purpose(claims, pur):
    """
    Check that the claims from a JWT have the expected purpose claim ``pur``.

    Args:
        claims (dict): claims from token
        pur (str): expected purpose

    Return:
        None

    Raises:
        JWTPurposeError:
            if the claims do not contain a purpose claim or if it doesn't match
            the expected value
    """
    if "pur" not in claims:
        raise JWTPurposeError("claims missing ``pur`` claim")
    if claims["pur"] != pur:
        raise JWTPurposeError(
            f"claims have incorrect purpose: expected {pur}, got {claims['pur']}"
        )


def validate_jwt(
    encoded_token: str,
    public_key: str | bytes,
    aud: str | list[str] | None = None,
    scope: set[str] | list[str] | None = None,
    allowed_issuers: set[str] | list[str] | None = None,
    purpose: str | None = None,
    options: dict | None = None,
    denylist_callback: Callable | None = None,
    logger: Callable | None = None,
) -> dict:
    """
    Validate the encoded JWT ``encoded_token``, which must satisfy the
    scopes ``scope``.

    This is just a slightly lower-level function to decode the token and
    perform the most basic checks on the token.

    - Decode JWT using public key; PyJWT will fail if iat or exp fields are
      invalid
    - PyJWT will also fail if the aud field is present in the JWT but no
      ``aud`` arg is passed, or if the ``aud`` arg does not match one of
      the items in the token aud field, because the audience is not validated
      anymore
    - Check allowed_issuers: token iss field must match one of the items in the
      ``allowed_issuers`` arg
    - Check scopes: token scopes must be a superset of required scopes
      (the ``scope`` argument); fail if not satisfied
    - Validate purpose: optional check of the ``pur`` claim
    - Denylist validation: optional callback to check if token is denylisted

    Args:
        encoded_token (str): encoded JWT
        public_key (str | bytes): public key to validate the JWT signature
        aud (str | list[str] | None):
          if provided, JWT validation will require that the token's ``aud`` value
          contains the arg value; if not provided, validation will require that
          the token not have an aud field.
        scope (set[str] | list[str] | None):
          set of scopes, each of which the JWT must satisfy in its
          ``scope`` claim. Optional.
        allowed_issuers (set[str] | list[str] | None): allowed allowed_issuers whitelist. If None, this will
            SKIP ISSUER VALIDATION. NOTE: THIS IS THE DEFAULT.
        options (dict | None): options to pass through to pyjwt's decode
        purpose (str | None): expected purpose of the token (e.g., 'access', 'refresh')
            IF PURPOSE IS NONE (DEFAULT) THIS SKIPS VALIDATION.
        denylist_callback (Callable | None): a callback function that takes
          (jti: str) and returns True if the token is denylisted.
          The callback is called after basic JWT validation.

    Returns:
        dict: the decoded and validated JWT

    Raises:
        ValueError: if receiving an incorrectly-typed argument
        JWTExpiredError: if token is expired
        JWTAudienceError: if aud validation fails
        JWTScopeError: if scope validation fails
        JWTPurposeError: if purpose validation fails
        JWTError: if some other token validation step fails, including if
          the denylist_callback indicates the token is denylisted
    """
    options = options or {}
    allowed_issuers = allowed_issuers or []

    if not isinstance(aud, str) and not isinstance(aud, list) and aud is not None:
        raise ValueError(
            f"aud must be string, list or None. Instead received aud of type {type(aud)}"
        )
    if not isinstance(scope, set) and not isinstance(scope, list) and scope is not None:
        raise ValueError(
            f"scope must be set or list or None. Instead received scope of type {type(scope)}"
        )
    if not isinstance(allowed_issuers, set) and not isinstance(allowed_issuers, list):
        raise ValueError(
            f"allowed_issuers must be set or list. Instead received allowed_issuers of type {type(allowed_issuers)}"
        )
    if purpose is not None and not isinstance(purpose, str):
        raise ValueError(
            f"purpose must be a string or None. Instead received purpose of type {type(purpose)}. Value: {purpose}"
        )
    if scope and isinstance(scope, list):
        scope = set(scope)

    try:
        token = jwt.decode(
            encoded_token,
            key=public_key,
            algorithms=["RS256"],
            audience=aud,
            options=Options(**options),
        )
    except jwt.InvalidAudienceError as e:
        # aud may not be in scope, use original value
        raise JWTAudienceError(
            f"token audience validation failed: expected {aud}, got unknown"
        )
    except jwt.ExpiredSignatureError as e:
        raise JWTExpiredError("token has expired")
    except jwt.InvalidTokenError as e:
        raise JWTError(f"token validation failed: {e}")

    # PyJWT validates iat, exp, and aud fields; everything else
    # must happen here.

    # iss
    # Check that the issuer of the token has the expected hostname.
    # Read with .get: a token carrying no iss at all must fail as a JWTError
    if allowed_issuers:
        token_iss = token.get("iss")
        if token_iss not in allowed_issuers:
            msg = f"invalid issuer {token_iss}; expected one of: {allowed_issuers}"
            raise JWTError(msg)

    # scope
    # Check that if scope arg was non-empty then the token includes each given scope in its scope claim
    if scope:
        token_scopes = token.get("scope", [])
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()
        if not isinstance(token_scopes, list):
            raise JWTError(
                f"invalid format in scope claim: {token.get('scopes')}; expected string or list"
            )
        missing_scopes = set(scope) - set(token_scopes)
        if missing_scopes:
            raise JWTScopeError(
                f"token is missing required scopes: {', '.join(sorted(missing_scopes))}"
            )

    # Validate the purpose claim if provided
    if purpose:
        validate_purpose(token, purpose)

    # Denylist validation: call the Denylist callback if provided
    if denylist_callback is not None:
        if not callable(denylist_callback):
            raise ValueError(
                "denylist_callback must be a callable that takes (jti) argument"
            )
        jti = token.get("jti", "")
        if denylist_callback(jti):
            raise JWTError("token is denylisted")

    return token


def _keys_url_candidates(
    issuer: str, force_issuer: bool | None = None
) -> tuple[str, str | None]:
    """
    Build the legacy keys URL and, unless forced, the OIDC discovery URL.

    Args:
        issuer (str): The token issuer.
        force_issuer (bool | None): Skip discovery and use /jwt/keys.

    Returns:
        tuple[str, str | None]: The /jwt/keys URL, and the discovery URL or
        None when discovery should be skipped.
    """
    jwt_keys_url = "/".join([issuer.strip("/"), "jwt", "keys"])
    if force_issuer:
        return jwt_keys_url, None
    openid_cfg_path = "/".join(
        [issuer.strip("/"), ".well-known", "openid-configuration"]
    )
    return jwt_keys_url, openid_cfg_path


def _log_discovery_fallback(
    openid_cfg_path: str, jwt_keys_url: str, exc: Exception
) -> None:
    """Log that OIDC discovery failed and the legacy keys URL will be used."""
    logging.info(
        f"Could not get public keys from: {openid_cfg_path}. Falling back to iss: {jwt_keys_url}. Exception: {exc}"
    )
