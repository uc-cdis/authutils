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
import binascii
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from typing import Any


from cdislogging import get_logger

try:
    import flask
except ImportError:
    print(
        "Unable to import flask. Some functionalities may not work. Flask can be installed as an extra."
    )
import httpx2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


from authutils.errors import JWTError
from .core import (
    KEYS_REQUEST_TIMEOUT,
    get_keys_url,
    get_keys_url_async,
    get_kid,
    get_iss,
)

logging = get_logger(__name__)

# In-memory cache for token public key lookups (with TTL)
# Maps "issuer:kid" to {"key": pem_key, "expires_at": timestamp}
# An OrderedDict so that eviction can be true LRU (move_to_end on read).
_token_public_key_cache: OrderedDict[str, dict] = OrderedDict()

# Maximum number of entries to cache to prevent memory overload
_TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE = 100

# Guards _token_public_key_cache. It is module-global and mutated (including
# iterated during eviction) from request threads, so unsynchronized access can
# raise "dictionary changed size during iteration".
_token_public_key_cache_lock = threading.Lock()


async def get_any_public_key_for_token_async(
    encoded_token: str,
    allowed_issuers: Iterable[str],
    cache_ttl: int = 300,
    logger: Any = None,
) -> bytes:
    """
    Get the public key for a token, without requiring a Flask app context.

    Includes an in-memory cache with TTL to avoid excessive network requests.

    Async-only by design. Discovery costs a DNS lookup plus up to two HTTP
    round trips on a cache miss, which a synchronous version would spend
    holding the caller's event loop. Flask services that need a key inside a
    request context should keep using get_public_key_for_token.

    The token's `kid` selects the key. If the token names a `kid` that the
    issuer does not publish, this raises.

    Args:
        encoded_token (str): Encoded JWT token.
        allowed_issuers (Iterable[str]): Exact-match allowlist of issuers,
            enforced before any outbound request. Required, and the only thing
            standing between an unverified `iss` claim and an outbound request
            to a host of the caller's choosing.
        cache_ttl (int): Cache time-to-live in seconds (default: 300s / 5 minutes).
        logger (Any): Logger instance. Defaults to module logger.

    Returns:
        bytes: Public key in PEM format.

    Raises:
        ValueError: If allowed_issuers is empty.
        JWTError: If the token is malformed, the issuer is not allowed, or the
            public key cannot be fetched or is not published by the issuer.
    """
    logger = logger or get_logger(__name__)

    allowed_issuers = set(allowed_issuers)
    if not allowed_issuers:
        raise ValueError(
            "allowed_issuers must be non-empty: it is what constrains which host "
            "key discovery will contact for an unverified iss claim."
        )

    try:
        iss = get_iss(encoded_token)
        token_kid = get_kid(encoded_token)
    except JWTError as e:
        raise JWTError(f"Could not extract issuer/kid from token: {str(e)}")

    if not iss:
        raise JWTError("Token is missing issuer (iss claim)")

    # Enforce the issuer allowlist before touching the network.
    _assert_issuer_allowed(iss, allowed_issuers, logger)

    cache_key = f"{iss}:{token_kid}"

    cached_key = _get_public_key_from_cache(cache_key, logger)
    if cached_key:
        return cached_key

    logger.debug(f"cache miss. attempting to get keys URL from iss: {iss}...")
    try:
        keys_url = await get_keys_url_async(iss)
    except Exception as exc:
        logger.error(exc, stack_info=True, exc_info=True)
        raise JWTError(f"Could not resolve keys URL for iss {iss}: {str(exc)}")

    try:
        logger.info(f"hitting keys URL from iss: {iss}, keys_url: {keys_url}...")
        jwks_data = await _fetch_jwks_async(keys_url)
    except Exception as exc:
        logger.error(exc, stack_info=True, exc_info=True)
        raise JWTError(f"Could not fetch JWKS from {keys_url}: {str(exc)}")

    pem_key = _pem_key_from_jwks(jwks_data, keys_url, token_kid, iss, logger)
    _save_public_key_to_cache(cache_key, pem_key, cache_ttl, logger)

    return pem_key


def clear_public_key_cache() -> None:
    """
    Empty the in-memory public key cache.

    Intended for tests and for operational cache invalidation after key
    rotation.
    """
    with _token_public_key_cache_lock:
        _token_public_key_cache.clear()


def get_pem_key(key, logger=None):
    """
    The key is serialized to PEM if not already.

    Return: tuple (key id, key in PEM format)
    """
    if "kty" in key and key["kty"] == "RSA":
        if logger:
            logger.debug(
                "Serializing RSA public key (kid: {}) to PEM format.".format(key["kid"])
            )
        # Decode public numbers https://tools.ietf.org/html/rfc7518#section-6.3.1
        n_padded_bytes = _strict_b64url_decode(key["n"], "n", key.get("kid"))
        e_padded_bytes = _strict_b64url_decode(key["e"], "e", key.get("kid"))
        n = int.from_bytes(n_padded_bytes, "big", signed=False)
        e = int.from_bytes(e_padded_bytes, "big", signed=False)
        # Serialize and encode public key--PyJWT decode/validation requires PEM
        rsa_public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        public_bytes = rsa_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # Cache the encoded key by issuer
        return key["kid"], public_bytes
    else:
        if logger:
            logger.debug(
                "Key type (kty) is not 'RSA'; assuming PEM format. Skipping key serialization. (kid: {})".format(
                    key[0]
                )
            )
        return key[0], key[1]


def refresh_jwt_public_keys(user_api=None, pkey_cache=None, logger=None):
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
        pkey_cache (Optional[dict]):
            public key cache for in memory (out of context application)

    Return:
        None

    Side Effects:
        - Reassign ``flask.current_app.jwt_public_keys[user_api]`` to the keys obtained
          from ``get_jwt_public_keys``, as a dictionary.

    Raises:
        ValueError: if user_api is not provided or set in app config
    """
    logger = logger or get_logger(__name__)
    if pkey_cache is None:
        pkey_cache = {}
    # First, make sure the app has a ``jwt_public_keys`` attribute set up.
    # This function is called both in application context and out of application context
    # trying to run current_app when its out of application context terminates the code wherever current_app is called
    if flask.has_app_context():
        missing_public_keys = (
            not hasattr(flask.current_app, "jwt_public_keys")
            or not flask.current_app.jwt_public_keys
        )
        if missing_public_keys:
            flask.current_app.jwt_public_keys = {}

    user_api = (
        (user_api or flask.current_app.get("USER_API"))
        if flask.has_app_context()
        else user_api
    )
    if not user_api:
        raise ValueError("no URL(s) provided for user API")

    force_issuer = (
        flask.current_app.config.get("FORCE_ISSUER")
        if flask.has_app_context()
        else None
    )
    path = get_keys_url(user_api, force_issuer)
    try:
        jwt_public_keys = httpx2.get(path).json()["keys"]
    except:
        raise JWTError(
            "Attempted to refresh public keys for {},"
            " but could not get keys from path {}.".format(user_api, path)
        )

    logger.info("Refreshing public key cache for issuer {}...".format(user_api))
    logger.debug(
        "Received public keys:\n{}".format(json.dumps(str(jwt_public_keys), indent=4))
    )

    issuer_public_keys = {}
    for key in jwt_public_keys:
        kid, pem_bytes = get_pem_key(key, logger)
        issuer_public_keys[kid] = pem_bytes

    if flask.has_app_context():
        flask.current_app.jwt_public_keys.update({user_api: issuer_public_keys})

    pkey_cache.update({user_api: issuer_public_keys})

    logger.info("Done refreshing public key cache for issuer {}.".format(user_api))


def get_public_key(kid, iss=None, attempt_refresh=True, pkey_cache=None, logger=None):
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
        pkey_cache (dict): also store pkey_cache in memory for cases where this function is used out of application context
            Used specifically for the Visa Update Cronjob (Access Token Polling)

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

    if pkey_cache is None:
        pkey_cache = {}

    iss = (
        iss
        or flask.current_app.config.get("OIDC_ISSUER")
        or flask.current_app.config["USER_API"]
    )
    logger = logger or get_logger(__name__)

    if flask.has_app_context():
        need_refresh = not hasattr(flask.current_app, "jwt_public_keys") or (
            kid and kid not in flask.current_app.jwt_public_keys.get(iss, {})
        )
    else:
        need_refresh = kid and kid not in pkey_cache.get(iss, {})

    if need_refresh and attempt_refresh:
        refresh_jwt_public_keys(iss, pkey_cache=pkey_cache, logger=logger)
    elif need_refresh and not attempt_refresh:
        logger.warning(
            "Public key {} not cached, but application is not attempting refresh.".format(
                kid
            )
        )

    if (
        flask.has_app_context() and iss not in flask.current_app.jwt_public_keys
    ) and iss not in pkey_cache:
        raise JWTError("Public key for issuer {} not found.".format(iss))

    iss_public_keys = (
        flask.current_app.jwt_public_keys[iss]
        if flask.has_app_context()
        else pkey_cache[iss]
    )
    try:
        return iss_public_keys[kid]
    except KeyError:
        raise JWTError("no key exists with given key id: {}".format(kid))


def get_public_key_for_token(
    encoded_token, attempt_refresh=True, pkey_cache=None, logger=None
):
    """
    Attempt to look up the public key which should be used to verify the token.

    Really just a thin wrapper around ``get_public_key`` which grabs the
    ``kid`` from the token headers and the ``iss`` from the token claims.

    Args:
        encoded_token (str): encoded JWT
        attempt_refresh (bool): whether to refresh public keys
        pkey_cache (dict): OPTIONAL store public key in in-memory cache for non-app context caching

    Return:
        str: public RSA key for token verification
    """
    logger = logger or get_logger(__name__)
    kid = get_kid(encoded_token)

    force_issuer = (
        flask.current_app.config.get("FORCE_ISSUER")
        if flask.has_app_context()
        else None
    )
    if force_issuer:
        iss = flask.current_app.config["USER_API"]
    else:
        iss = get_iss(encoded_token)
    return get_public_key(
        kid,
        iss=iss,
        attempt_refresh=attempt_refresh,
        pkey_cache=pkey_cache,
        logger=logger,
    )


def _assert_issuer_allowed(
    iss: str, allowed_issuers: Iterable[str], logger: Any = None
) -> None:
    """
    Verify an unverified `iss` claim before it is used for key discovery.
    Key discovery makes outbound HTTP requests derived from `iss`.

    Args:
        iss (str): The issuer claim taken from the unverified token.
        allowed_issuers (Iterable[str]): Exact-match allowlist of issuers.
        logger (Any): Logger instance. Defaults to module logger.

    Raises:
        JWTError: If the issuer is not in the allowlist.
    """
    logger = logger or get_logger(__name__)

    if iss not in set(allowed_issuers):
        raise JWTError(
            f"Token issuer is not in the allowed issuers list: {iss}. "
            "Refusing to perform key discovery for an untrusted issuer."
        )


async def _fetch_jwks_async(keys_url: str) -> Any:
    """
    Fetch and parse a JWKS document.

    The single outbound-request seam for key discovery, which keeps the
    transport in one place and gives tests one thing to stub.

    Args:
        keys_url (str): The validated JWKS / keys URL.

    Returns:
        Any: The parsed response body.

    Raises:
        httpx2.HTTPError: If the request fails or returns an error status.
    """
    async with httpx2.AsyncClient(
        timeout=httpx2.Timeout(timeout=KEYS_REQUEST_TIMEOUT)
    ) as client:
        response = await client.get(keys_url)
    response.raise_for_status()
    return response.json()


def _pem_key_from_jwks(
    jwks_data: Any, keys_url: str, token_kid: str | None, iss: str, logger: Any
) -> bytes:
    """
    Select the token's key from a fetched JWKS document and serialize it.

    Args:
        jwks_data (Any): The parsed JWKS response body.
        keys_url (str): The URL it came from, for error messages.
        token_kid (str | None): The kid from the token header, if any.
        iss (str): The issuer, for error messages.
        logger (Any): Logger instance.

    Returns:
        bytes: Public key in PEM format.

    Raises:
        JWTError: If the document carries no usable keys, does not publish the
            token's kid, or the selected key cannot be serialized.
    """
    if not jwks_data or isinstance(jwks_data, str):
        logger.error(f"invalid jwks data: {jwks_data}")
        raise JWTError(
            f"Could not fetch JWKS from {keys_url}. Response JSON is empty or a string."
        )

    # Safely extract keys array (handles root dict or fallback list)
    raw_keys = jwks_data.get("keys", []) if isinstance(jwks_data, dict) else jwks_data
    keys_by_id = _build_keys_by_id(raw_keys, logger)

    if not keys_by_id:
        raise JWTError(f"Got no keys from {keys_url} for iss: {iss}")

    selected_kid, key_data = _select_key(keys_by_id, token_kid, iss, logger)

    try:
        _, pem_key = get_pem_key(key_data, logger)
    except Exception as exc:
        logger.error(exc, stack_info=True, exc_info=True)
        raise JWTError(
            f"Could not serialize public key for kid={selected_kid} "
            f"at issuer {iss}: {exc}"
        )

    if not pem_key:
        raise JWTError(
            f"Public key for kid={selected_kid} at issuer {iss} is empty or unusable"
        )

    return pem_key


def _build_keys_by_id(
    raw_keys: Iterable[Any], logger: Any = None
) -> OrderedDict[str, Any]:
    """
    Index a JWKS response by key id, preserving document order.

    Handles both the official JWKS object format and the legacy `/jwt/keys`
    `[kid, pem]` pair format. Legacy entries keep their `(kid, pem)` shape
    so that get_pem_key, which unpacks positionally, still works on them.

    Args:
        raw_keys (Iterable[Any]): The `keys` array from a JWKS response.
        logger (Any): Logger instance.

    Returns:
        OrderedDict[str, Any]: kid -> JWK dict or (kid, pem) pair.
    """
    keys_by_id: OrderedDict[str, Any] = OrderedDict()

    for item in raw_keys or []:
        # Legacy custom format: ["kid", "-----BEGIN PUBLIC KEY..."]
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            keys_by_id[item[0]] = item

        # Official .well-known JWKS format: {"kid": "...", "kty": "RSA", ...}
        elif isinstance(item, dict) and "kid" in item:
            keys_by_id[item["kid"]] = item

        elif logger:
            logger.debug(f"Skipping unrecognized JWKS entry: {type(item).__name__}")

    return keys_by_id


def _select_key(
    keys_by_id: OrderedDict[str, Any],
    token_kid: str | None,
    iss: str,
    logger: Any = None,
) -> tuple[str, Any]:
    """
    Choose the published key that the token's `kid` names.

    A kid the issuer does not publish is an error.
    Only a token declaring no kid at all falls back to the first published key.

    Args:
        keys_by_id (OrderedDict[str, Any]): kid -> key data, in document order.
        token_kid (str | None): The kid from the token header, if any.
        iss (str): Issuer, used for error messages.
        logger (Any): Logger instance. Defaults to module logger.

    Returns:
        tuple[str, Any]: The selected kid and its key data.

    Raises:
        JWTError: If the token names a kid the issuer does not publish.
    """
    logger = logger or get_logger(__name__)

    if token_kid is not None:
        if token_kid not in keys_by_id:
            raise JWTError(
                f"No public key found for kid={token_kid} at issuer {iss}. "
                f"Issuer publishes: {list(keys_by_id)}"
            )
        return token_kid, keys_by_id[token_kid]

    selected_kid, key_data = next(iter(keys_by_id.items()))
    logger.debug(
        f"Token declared no kid; using first published key {selected_kid!r} "
        f"from issuer {iss}"
    )
    return selected_kid, key_data


def _strict_b64url_decode(value: str, param: str, kid: Any = None) -> bytes:
    """
    Base64url-decode a JWK parameter, rejecting characters outside the alphabet.

    base64.urlsafe_b64decode silently DISCARDS non-alphabet characters, so a
    JWKS advertising n="!!!not-base64!!!" would otherwise yield a small but
    structurally valid RSA key rather than an error. Every token checked
    against it then fails signature verification, which reads as "bad token"
    instead of "the issuer published a malformed key".

    Args:
        value (str): The base64url-encoded parameter value.
        param (str): Parameter name, for the error message.
        kid (Any): Key id, for the error message.

    Returns:
        bytes: The decoded bytes.

    Raises:
        JWTError: If the value is empty or is not valid base64url.
    """
    if not value or not isinstance(value, str):
        raise JWTError(f"JWKS key (kid: {kid}) has an empty '{param}' parameter")

    try:
        # validate=True is the important flag here: urlsafe_b64decode drops stray characters
        # with validate=false (default) instead of failing.
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except binascii.Error as exc:
        raise JWTError(
            f"JWKS key (kid: {kid}) has a malformed '{param}' parameter: {exc}"
        )


def _get_public_key_from_cache(cache_key: str, logger: Any = None) -> bytes | None:
    """
    Retrieve a public key from cache if it exists and hasn't expired.

    Args:
        cache_key (str): Cache key in format "issuer:kid".
        logger (Any): Logger instance.

    Returns:
        bytes | None: Public key in PEM format if valid entry exists, None otherwise.
    """
    with _token_public_key_cache_lock:
        cached_entry = _token_public_key_cache.get(cache_key)
        if cached_entry is None:
            return None

        if time.time() < cached_entry["expires_at"]:
            # Mark as recently used so eviction is LRU.
            _token_public_key_cache.move_to_end(cache_key)
            if logger:
                logger.debug(f"Using cached public key for {cache_key}")
            return cached_entry["key"]

        del _token_public_key_cache[cache_key]
        return None


def _save_public_key_to_cache(
    cache_key: str, pem_key: bytes, cache_ttl: int, logger: Any = None
) -> None:
    """
    Save a public key to cache with TTL, enforcing cache size limits via LRU eviction.

    Args:
        cache_key (str): Cache key in format "issuer:kid".
        pem_key (bytes): Public key in PEM format.
        cache_ttl (int): Cache time-to-live in seconds.
        logger (Any): Logger instance.

    Side Effects:
        - Adds entry to _token_public_key_cache.
        - May evict the least-recently-used entry if the cache is at capacity.
    """
    with _token_public_key_cache_lock:
        # Cache the key (move_to_end keeps insertion/refresh at the MRU end)
        _token_public_key_cache[cache_key] = {
            "key": pem_key,
            "expires_at": time.time() + cache_ttl,
        }
        _token_public_key_cache.move_to_end(cache_key)

        # Enforce cache size limit: evict least-recently-used entries.
        while len(_token_public_key_cache) > _TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE:
            evicted_key, _ = _token_public_key_cache.popitem(last=False)
            if logger:
                logger.debug(
                    f"Cache at capacity ({_TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE}), "
                    f"evicted least-recently-used entry: {evicted_key}"
                )
