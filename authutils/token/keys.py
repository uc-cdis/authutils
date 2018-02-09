from collections import OrderedDict
import json

import flask
import requests


from authutils.errors import JWTError


def refresh_jwt_public_keys(user_api=None):
    """
    Update the public keys that the Flask app is currently using to validate
    JWTs.

    Response from ``/jwt/keys`` should look like this:

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

    Take out the array of keys, put it in an ordered dictionary, and assign
    that to ``flask.current_app.jwt_public_keys``.

    Args:
        user_api (Optional[str]):
            the URL of the user API to get the keys from; default to whatever
            the flask app is configured to use

    Return:
        None

    Side Effects:
        - Reassign ``flask.current_app.jwt_public_keys`` to the keys obtained
          from ``get_jwt_public_keys``, as an OrderedDict.

    Raises:
        ValueError: if user_api is not provided or set in app config
    """
    user_api = user_api or flask.current_app.config.get('USER_API')
    if not user_api:
        raise ValueError('no URL provided for user API')
    path = '/'.join(path.strip('/') for path in [user_api, 'jwt', 'keys'])
    jwt_public_keys = requests.get(path).json()['keys']
    flask.current_app.logger.info(
        'refreshing public keys; updated to:\n'
        + json.dumps(jwt_public_keys, indent=4)
    )
    flask.current_app.jwt_public_keys = OrderedDict(jwt_public_keys)


def get_public_key_for_kid(kid, attempt_refresh=True):
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
    need_refresh = (
        not hasattr(flask.current_app, 'jwt_public_keys')
        or (kid and kid not in flask.current_app.jwt_public_keys)
    )
    if need_refresh and attempt_refresh:
        refresh_jwt_public_keys()
    if kid:
        try:
            return flask.current_app.jwt_public_keys[kid]
        except KeyError:
            raise JWTError('no key exists with given key id: {}'.format(kid))
    else:
        # Grab the key from the first in the list of keys.
        return flask.current_app.jwt_public_keys.items()[0][1]
