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
    aud,
    purpose="access",
    issuers=None,
    public_key=None,
    attempt_refresh=True,
    logger=None,
):
    """
    Validate a JWT and return the claims.

    Args:
        encoded_token (str): the base64 encoding of the token
        aud (Optional[Iterable[str]]):
            list of audiences that the token must satisfy; defaults to
            ``{'openid'}`` (minimum expected by OpenID provider)
        purpose (Optional[str]):
            which purpose the token is supposed to be used for (access,
            refresh, or id)
        issuers (Iterable[str]): list of allowed token issuers
        public_key (Optional[str]): public key to vaidate JWT with

    Return:
        dict: dictionary of claims from the validated JWT

    Raises:
        ValueError: if ``aud`` is empty
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
    if public_key is None:
        public_key = get_public_key_for_token(
            encoded_token, attempt_refresh=attempt_refresh, logger=logger
        )
    if not aud:
        raise ValueError("must provide at least one audience")
    aud = set(aud)
    claims = core.validate_jwt(encoded_token, public_key, aud, issuers)
    if purpose:
        core.validate_purpose(claims, purpose)
    return claims


def validate_request(aud, purpose="access", logger=None):
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
    return validate_jwt(encoded_token, aud, purpose, logger=logger)


def require_auth_header(aud, purpose=None, logger=None):
    """
    Return a decorator which adds request validation to check the given
    audiences and (optionally) purpose.
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
            set_current_token(validate_request(aud=aud, purpose=purpose, logger=logger))
            return f(*args, **kwargs)

        return wrapper

    return decorator
