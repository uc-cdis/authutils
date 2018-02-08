from authlib.client.errors import OAuthException
from authlib.specs.rfc6749.errors import OAuth2Error
import flask
from flask import current_app

from authutils.errors import AuthError
from authutils.token import set_current_token, store_session_token


def client_do_authorize():
    redirect_uri = current_app.oauth_client.session.redirect_uri
    try:
        assert flask.request.args['state'] == flask.session.pop('state')
    except (KeyError, AssertionError):
        raise AuthError(
            'could not authorize; state did not match across auth requests'
        )
    try:
        token = current_app.oauth_client.fetch_access_token(
            redirect_uri, **flask.request.args.to_dict()
        )
        store_session_token(token['access_token'])
        return token
    except KeyError as e:
        raise AuthError('error in token response: {}'.format(token))
    except (OAuth2Error, OAuthException) as e:
        raise AuthError(str(e))
