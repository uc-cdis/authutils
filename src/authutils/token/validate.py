# pylint: disable=protected-access
"""
Define functions for validating a JWT and tracking the current token and claims
from a request.
"""

import flask
import functools
from cdislogging import get_logger
from werkzeug.local import LocalProxy

from . import core
from .keys import get_public_key_for_token
from ..errors import JWTError

#: Proxy for the current token, which gets assigned to in
#: ``require_auth_header``, so any function using that as a decorator can then
#: use ``current_token`` to get the claims for the token.
#:
#: (Note that this should really be called `set_current_claims`, since we're
#: using the claims here and not the raw token, which *is* what gets used for
#: `store_session_token`/`get_session_token`.)
#:
#: Anything that needs to check a JWT should try to use this, and set it if it
#: wasn't already, to avoid redundant validation.
current_token = LocalProxy(lambda: getattr(flask.g, "_current_token", None))


def set_current_token(token):
    flask.g._current_token = token


def store_session_token(token):
    flask.session["_authutils_access_token"] = token


def get_jwt_token():
    """
    Get the current JWT (in encoded form), from a bearer auth header.

    Requires flask request context.

    Return:
        str: encoded token
    """
    auth_header = flask.request.headers.get("Authorization")
    token = None
    if auth_header:
        items = auth_header.split(" ")
        if len(items) == 2 and items[0].lower() == "bearer":
            token = items[1]
    return token


def get_session_token():
    """
    Get the current JWT (in encoded form), from either a bearer auth header or
    the `_authutils_access_token` in the flask session.

    Requires flask request context and a matching Session interface.

    Return:
        str: encoded token
    """
    return get_jwt_token() or flask.session.get("_authutils_access_token")


def validate_jwt(
    encoded_token,
    aud=None,
    scope=None,
    purpose="access",
    issuers=None,
    public_key=None,
    attempt_refresh=True,
    logger=None,
    options={},
):
    """
    Validate a JWT and return the claims.

    Args:
        encoded_token (str): the base64 encoding of the token
        aud (Optional[str]):
            audience as which the app identifies, which the JWT will be
            expected to include in its ``aud`` claim.
            Optional; will default to issuer from flask.current_app.config
            if available (either BASE_URL or USER_API).
            To skip aud validation, pass the following in the options arg:
              options={"verify_aud": False}
        scope (Optional[Iterable[str]]):
            scopes that the token must satisfy
        purpose (Optional[str]):
            which purpose the token is supposed to be used for (access,
            refresh, or id)
        issuers (Iterable[str]): list of allowed token issuers
        public_key (Optional[str]): public key to vaidate JWT with
        attempt_refresh (Optional[bool]):
            whether to attempt refresh of public keys if not found in cache
        options (Optional[dict]): options to pass through to pyjwt's decode

    Return:
        dict: dictionary of claims from the validated JWT

    Raises:
        JWTError:
            if auth header is missing, decoding fails, or the JWT fails to
            satisfy any expectation
    """
    logger = logger or get_logger(__name__, log_level="info")

    if not issuers:
        issuers = []
        for config_var in ["OIDC_ISSUER", "USER_API", "BASE_URL"]:
            value = flask.current_app.config.get(config_var)
            if value:
                issuers.append(value)

    # Can't set arg default to config[x] in fn def, so doing it this way.
    if aud is None:
        aud = flask.current_app.config.get("BASE_URL")
    # Some Gen3 apps use BASE_URL and some use USER_API, so fall back on USER_API
    if aud is None:
        aud = flask.current_app.config.get("USER_API")

    if public_key is None:
        public_key = get_public_key_for_token(
            encoded_token, attempt_refresh=attempt_refresh, logger=logger
        )

    claims = core.validate_jwt(encoded_token, public_key, aud, scope, issuers, options)
    if purpose:
        core.validate_purpose(claims, purpose)
    return claims


def validate_request(scope={}, audience=None, purpose="access", logger=None):
    """
    Validate a ``flask.request`` by checking the JWT contained in the request
    headers.
    """
    logger = logger or get_logger(__name__, log_level="info")
    # Get token from the headers.
    try:
        encoded_token = flask.request.headers["Authorization"].split(" ")[1]
    except IndexError:
        raise JWTError("could not parse authorization header")
    except KeyError:
        raise JWTError("no authorization header provided")

    # Pass token to ``validate_jwt``.
    return validate_jwt(
        encoded_token,
        aud=audience,
        scope=scope,
        purpose=purpose,
        logger=logger,
    )


def require_auth_header(scope={}, audience=None, purpose=None, logger=None):
    """
    Return a decorator which adds request validation to check the given
    scopes, audience and purpose (all optional).
    """
    logger = logger or get_logger(__name__, log_level="info")

    def decorator(f):
        """
        Decorate the given function to check for a valid JWT header.
        """

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            """
            Wrap a function to first validate the request header token.

            Assign the claims from the token to ``flask.g._current_token`` so
            the code inside the function can use the ``LocalProxy`` for the
            token (see top of this file).
            """
            set_current_token(
                validate_request(
                    scope=scope, audience=audience, purpose=purpose, logger=logger
                )
            )
            return f(*args, **kwargs)

        return wrapper

    return decorator
