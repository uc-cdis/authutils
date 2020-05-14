import jwt

from ..errors import JWTAudienceError, JWTExpiredError, JWTPurposeError, JWTError


def get_keys_url(issuer):
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


def validate_jwt(encoded_token, public_key, aud, issuers):
    """
    Validate the encoded JWT ``encoded_token``, which must satisfy the
    audiences ``aud``.

    This is just a slightly lower-level function to decode the token and
    perform the most basic checks on the token.

    - Decode JWT using public key; PyJWT will fail if iat or exp fields are
      invalid
    - Check audiences: token audiences must be a superset of required audiences
      (the ``aud`` argument); fail if not satisfied

    Args:
        encoded_token (str): encoded JWT
        public_key (str): public key to validate the JWT signature
        aud (set): non-empty set of audiences the JWT must satisfy
        issuers (list or set): allowed issuers whitelist

    Return:
        dict: the decoded and validated JWT

    Raises:
        ValueError: if receiving an incorrectly-typed argument
        JWTValidationError: if any step of the validation fails
    """
    # Typecheck arguments.
    if not isinstance(aud, set) and not isinstance(aud, list):
        raise ValueError("aud must be set or list")
    if not isinstance(issuers, set) and not isinstance(issuers, list):
        raise ValueError("issuers must be set or list")

    # To satisfy PyJWT, since the token will contain an aud field, decode has
    # to be passed one of the audiences to check here (so PyJWT doesn't raise
    # an InvalidAudienceError). Per the JWT specification, if the token
    # contains an aud field, the validator MUST identify with one of the
    # audiences listed in that field. This implementation is more strict, and
    # allows the validator to demand multiple audiences which must all be
    # satisfied by the token (see below).
    aud = set(aud)
    random_aud = list(aud)[0]
    try:
        token = jwt.decode(
            encoded_token, key=public_key, algorithms=["RS256"], audience=random_aud
        )
    except jwt.InvalidAudienceError as e:
        raise JWTAudienceError(e)
    except jwt.ExpiredSignatureError as e:
        raise JWTExpiredError(e)
    except jwt.InvalidTokenError as e:
        raise JWTError(e)

    # PyJWT validates iat and exp fields (and aud...sort of); everything else
    # must happen here.

    # iss
    # Check that the issuer of the token has the expected hostname.
    if token["iss"] not in issuers:
        msg = "invalid issuer {}; expected: {}".format(token["iss"], issuers)
        raise JWTError(msg)

    # aud
    # The audiences listed in the token must completely satisfy all the
    # required audiences provided. Note that this is stricter than the
    # specification suggested in RFC 7519.
    missing = aud - set(token["aud"])
    if missing:
        raise JWTAudienceError("missing audiences: " + str(missing))

    return token
