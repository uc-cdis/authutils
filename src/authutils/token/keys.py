"""
Define functions for updating the public keys associated with certain token
issuers and retrieving the public key which can be used to verify a given JWT.

The public keys should be stored on the flask app in a `jwt_public_keys`
attribute, which will be a dictionary mapping issuer URLs (`iss` in a JWT) to
ordered dictionaries mapping key IDs to public key strings.

For example:

.. code-block:: python

    flask.current_app.jwt_public_keys == {
        'http://some-gen3-stack.net/user': OrderedDict([
            'key-01': '-----BEGIN PUBLIC KEY-----...',
            'key-02': '-----BEGIN PUBLIC KEY-----...',
        ]),
        'http://different-gen3-site.org/user': OrderedDict([
            'key-01': '-----BEGIN PUBLIC KEY-----...',
        ]),
    }
"""

import base64
import json
from collections import OrderedDict

from cdislogging import get_logger
import flask
import jwt
import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


from authutils.errors import JWTError
from .core import get_keys_url, get_kid, get_iss


def refresh_jwt_public_keys(user_api=None, logger=None):
    """
    Update the public keys that the Flask app is currently using to validate
    JWTs.

    The get_keys_url helper function will prefer the user_api's
    .well-known/openid-configuration endpoint, but if no jwks_uri
    is found, will default to /jwt/keys.

    In the latter case, the response from ``/jwt/keys`` should look like this:

    .. code-block:: javascript

    {
        "keys": [
            [
                "key-id-01",
                "-----BEGIN PUBLIC KEY---- ... -----END PUBLIC KEY-----\n"
            ],
            [
                "key-id-02",
                "-----BEGIN PUBLIC KEY---- ... -----END PUBLIC KEY-----\n"
            ]
        ]
    }

    In either case, the keys are put into a dictionary and assigned to
    ``flask.current_app.jwt_public_keys`` with user_api as the key.
    Keys are serialized to PEM if not already.

    Args:
        user_api (Optional[str]):
            the URL of the user API to get the keys from; default to whatever
            the flask app is configured to use
        logger (Optional[Logger]):
            the logger; default to app's parent logger

    Return:
        None

    Side Effects:
        - Reassign ``flask.current_app.jwt_public_keys[user_api]`` to the keys obtained
          from ``get_jwt_public_keys``, as a dictionary.

    Raises:
        ValueError: if user_api is not provided or set in app config
    """
    logger = logger or get_logger(__name__, log_level="info")
    # First, make sure the app has a ``jwt_public_keys`` attribute set up.
    missing_public_keys = (
        not hasattr(flask.current_app, "jwt_public_keys")
        or not flask.current_app.jwt_public_keys
    )
    if missing_public_keys:
        flask.current_app.jwt_public_keys = {}
    user_api = user_api or flask.current_app.config.get("USER_API")
    if not user_api:
        raise ValueError("no URL(s) provided for user API")

    path = get_keys_url(user_api)
    try:
        jwt_public_keys = httpx.get(path).json()["keys"]
    except:
        raise JWTError(
            "Attempted to refresh public keys for {},"
            "but could not get keys from path {}.".format(user_api, path)
        )

    logger.info("Refreshing public key cache for issuer {}...".format(user_api))
    logger.debug(
        "Received public keys:\n{}".format(json.dumps(str(jwt_public_keys), indent=4))
    )

    issuer_public_keys = {}
    for key in jwt_public_keys:
        if "kty" in key and key["kty"] == "RSA":
            logger.debug(
                "Serializing RSA public key (kid: {}) to PEM format.".format(key["kid"])
            )
            # Decode public numbers https://tools.ietf.org/html/rfc7518#section-6.3.1
            n_padded_bytes = base64.urlsafe_b64decode(
                key["n"] + "=" * (4 - len(key["n"]) % 4)
            )
            e_padded_bytes = base64.urlsafe_b64decode(
                key["e"] + "=" * (4 - len(key["e"]) % 4)
            )
            n = int.from_bytes(n_padded_bytes, "big", signed=False)
            e = int.from_bytes(e_padded_bytes, "big", signed=False)
            # Serialize and encode public key--PyJWT decode/validation requires PEM
            rsa_public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
            public_bytes = rsa_public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            # Cache the encoded key by issuer
            issuer_public_keys[key["kid"]] = public_bytes
        else:
            logger.debug(
                "Key type (kty) is not 'RSA'; assuming PEM format. Skipping key serialization. (kid: {})".format(
                    key[0]
                )
            )
            issuer_public_keys[key[0]] = key[1]

    flask.current_app.jwt_public_keys.update({user_api: issuer_public_keys})
    logger.info("Done refreshing public key cache for issuer {}.".format(user_api))


def get_public_key(kid, iss=None, attempt_refresh=True, logger=None):
    """
    Given a key id ``kid``, get the public key from the flask app belonging to
    this key id. The key id is allowed to be None, in which case, use the the
    first key in the OrderedDict.

    - If current flask app is not holding public keys (ordered dictionary) or
      key id is in token headers and the key id does not appear in those public
      keys, refresh the public keys by calling ``refresh_jwt_public_keys()``
    - If key id is provided in the token headers:
      - If key id does not appear in public keys, fail
      - Use public key with this key id
    - If key id is not provided:
      - Use first public key in the ordered dictionary

    Args:
        kid (str): the key id
        attempt_refresh (bool):
            whether to try to refresh the public keys of the flask app if
            encountering a key id that does not exist in those keys; for fence
            itself this should be ``False``, and for other services it should
            be ``True``

    Return:
        str: the public key

    Side Effects:
        - From ``refresh_jwt_public_keys``: reassign
          ``flask.current_app.jwt_public_keys`` to the keys obtained from
          ``get_jwt_public_keys``.

    Raises:
        JWTValidationError:
            if the key id is provided and public key with that key id is found
    """

    iss = (
        iss
        or flask.current_app.config.get("OIDC_ISSUER")
        or flask.current_app.config["USER_API"]
    )
    logger = logger or get_logger(__name__, log_level="info")
    need_refresh = not hasattr(flask.current_app, "jwt_public_keys") or (
        kid and kid not in flask.current_app.jwt_public_keys.get(iss, {})
    )
    if need_refresh and attempt_refresh:
        refresh_jwt_public_keys(iss, logger=logger)
    elif need_refresh and not attempt_refresh:
        logger.warn(
            "Public key {} not cached, but application is not attempting refresh.".format(
                kid
            )
        )

    if iss not in flask.current_app.jwt_public_keys:
        raise JWTError("Public key for issuer {} not found.".format(iss))

    iss_public_keys = flask.current_app.jwt_public_keys[iss]
    try:
        return iss_public_keys[kid]
    except KeyError:
        raise JWTError("no key exists with given key id: {}".format(kid))


def get_public_key_for_token(encoded_token, attempt_refresh=True, logger=None):
    """
    Attempt to look up the public key which should be used to verify the token.

    Really just a thin wrapper around ``get_public_key`` which grabs the
    ``kid`` from the token headers and the ``iss`` from the token claims.

    Args:
        encoded_token (str): encoded JWT
        attempt_refresh (bool): whether to refresh public keys

    Return:
        str: public RSA key for token verification
    """
    logger = logger or get_logger(__name__, log_level="info")
    kid = get_kid(encoded_token)

    force_issuer = flask.current_app.config.get("FORCE_ISSUER")
    if force_issuer:
        iss = flask.current_app.config["USER_API"]
    else:
        iss = get_iss(encoded_token)
    return get_public_key(kid, iss=iss, attempt_refresh=attempt_refresh, logger=logger)
