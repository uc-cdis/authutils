import httpx
import jwt

from ..errors import (
    JWTAudienceError,
    JWTExpiredError,
    JWTPurposeError,
    JWTScopeError,
    JWTError,
)


def get_keys_url(issuer):
    # Prefer OIDC discovery doc, but fall back on Fence-specific /jwt/keys for backwards compatibility
    openid_cfg_path = "/".join(
        [issuer.strip("/"), ".well-known", "openid-configuration"]
    )
    try:
        jwks_uri = httpx.get(openid_cfg_path).json().get("jwks_uri", "")
        return jwks_uri
    except:
        return "/".join([issuer.strip("/"), "jwt", "keys"])


def get_kid(encoded_token):
    try:
        return jwt.get_unverified_header(encoded_token).get("kid")
    except jwt.InvalidTokenError as e:
        raise JWTError(e)


def get_iss(encoded_token):
    try:
        return jwt.decode(encoded_token, verify=False).get("iss")
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


def validate_jwt(encoded_token, public_key, aud, scope, issuers, options={}):
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

    # Typecheck arguments.
    if not isinstance(aud, str) and not aud is None:
        raise ValueError(
            "aud must be string or None. Instead received aud of type {}".format(
                type(aud)
            )
        )
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

    try:
        token = jwt.decode(
            encoded_token,
            key=public_key,
            algorithms=["RS256"],
            audience=aud,
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
