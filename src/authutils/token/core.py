import httpx
import jwt

from cdislogging import get_logger

from ..errors import (
    JWTAudienceError,
    JWTExpiredError,
    JWTPurposeError,
    JWTScopeError,
    JWTError,
)


def get_keys_url(issuer, force_issuer=None):
    """
    Prefer OIDC discovery doc, but fall back on Fence-specific /jwt/keys for backwards compatibility (or if `force_issuer` is True)
    """
    jwt_keys_url = "/".join([issuer.strip("/"), "jwt", "keys"])
    if force_issuer:
        return jwt_keys_url

    openid_cfg_path = "/".join(
        [issuer.strip("/"), ".well-known", "openid-configuration"]
    )
    try:
        jwks_uri = httpx.get(openid_cfg_path).json().get("jwks_uri", "")
        return jwks_uri
    except:
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
        raise JWTPurposeError("claims missing `pur` claim")
    if claims["pur"] != pur:
        raise JWTPurposeError(
            "claims have incorrect purpose: expected {}, got {}".format(
                pur, claims["pur"]
            )
        )


def validate_jwt(
    encoded_token, public_key, aud, scope, issuers, options={}, logger=None
):
    """
    Validate the encoded JWT ``encoded_token``, which must satisfy the
    scopes ``scope``.

    This is just a slightly lower-level function to decode the token and
    perform the most basic checks on the token.

    - Decode JWT using public key; PyJWT will fail if iat or exp fields are
      invalid
    - PyJWT will also fail if the aud field is present in the JWT but no
      ``aud`` arg is passed, or if the ``aud`` arg does not match one of
      the items in the token aud field
    - Check issuers: token iss field must match one of the items in the
      ``issuers`` arg
    - Check scopes: token scopes must be a superset of required scopes
      (the ``scope`` argument); fail if not satisfied

    Args:
        encoded_token (str): encoded JWT
        public_key (str): public key to validate the JWT signature
        aud (Optional[str]):
          audience with which the app identifies, usually an OIDC
          client id, which the JWT will be expected to include in its ``aud``
          claim. Optional; if no ``aud`` argument given, then the JWT must
          not have an ``aud`` claim, or validation will fail.
        scope (Optional[Iterable[str]]):
          set of scopes, each of which the JWT must satisfy in its
          ``scope`` claim. Optional.
        issuers (list or set): allowed issuers whitelist
        options (Optional[dict]): options to pass through to pyjwt's decode

    Return:
        dict: the decoded and validated JWT

    Raises:
        ValueError: if receiving an incorrectly-typed argument
        JWTExpiredError: if token is expired
        JWTAudienceError: if aud validation fails
        JWTScopeError: if scope validation fails
        JWTError: if some other token validation step fails
    """
    logger = logger or get_logger(__name__, log_level="info")

    # Typecheck arguments.
    if not isinstance(scope, set) and not isinstance(scope, list) and not scope is None:
        raise ValueError(
            "scope must be set or list or None. Instead received scope of type {}".format(
                type(scope)
            )
        )
    if not isinstance(issuers, set) and not isinstance(issuers, list):
        raise ValueError(
            "issuers must be set or list. Instead received issuers of type {}".format(
                type(issuers)
            )
        )

    # Skip audience validation.
    # Background: authutils is used by internal Gen3 services asking if they can use a Gen3 Fence
    # token. Each Gen3 service was setting `aud=<Fence URL>` which is not the way the audience
    # field is supposed to be used: we were checking that fence was in the list, which it always
    # was if fence generated it, so this provided no further protection beyond general JWT / public
    # key verification and validation. The validation of which Gen3 instance the token is meant for
    # is already done by using the issuer (`iss` field) to get public keys and verify the signature.
    if aud is not None:
        logger.warning(
            f"Authutils no longer validates the token's `aud` field. Received {aud=} which will be ignored."
        )
    options["verify_aud"] = False

    try:
        token = jwt.decode(
            encoded_token,
            key=public_key,
            algorithms=["RS256"],
            options=options,
        )
    except jwt.InvalidAudienceError as e:
        raise JWTAudienceError(e)
    except jwt.ExpiredSignatureError as e:
        raise JWTExpiredError(e)
    except jwt.InvalidTokenError as e:
        raise JWTError(e)

    # PyJWT validates iat, exp, and aud fields; everything else
    # must happen here.

    # iss
    # Check that the issuer of the token has the expected hostname.
    if token["iss"] not in issuers:
        msg = "invalid issuer {}; expected: {}".format(token["iss"], issuers)
        raise JWTError(msg)

    # scope
    # Check that if scope arg was non-empty then the token includes each given scope in its scope claim
    if scope:
        token_scopes = token.get("scope", [])
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()
        if not isinstance(token_scopes, list):
            raise JWTError(
                "invalid format in scope claim: {}; expected string or list".format(
                    token["scopes"]
                )
            )
        missing_scopes = set(scope) - set(token_scopes)
        if missing_scopes:
            raise JWTScopeError(
                "token is missing required scopes: " + str(missing_scopes)
            )

    return token
