"""
Provide a basic set of endpoints for an application to implement OAuth client
functionality.

These endpoints assume that the ``current_app`` has already been configured
with an OAuth client instance from the ``authlib`` package as follows:

.. code-block:: python

    from authutils.oauth2.client import OAuthClient
    from service.api import app

    app.oauth_client = OAuthClient(
        'client-id',
        client_secret='...',
        api_base_url='https://api.auth.net/',
        access_token_url='https://auth.net/oauth/token',
        authorize_url='https://auth.net/oauth/authorize',
        client_kwargs={
            'scope': 'data:user',
            'redirect_uri': 'https://service.net/authorize',
        },
    )
"""

import flask
from flask import current_app

from authutils.errors import AuthError


blueprint = flask.Blueprint('oauth', __name__)


@blueprint.route('/authorization_url', methods=['GET'])
def get_authorization_url():
    """
    Provide a redirect to the authorization endpoint from the OP.
    """
    # This will be the value that was put in the ``client_kwargs`` in config.
    callback_uri = current_app.oauth_client.session.callback_uri
    # Get the authorization URL and the random state; save the state to check
    # later, and return the URL.
    authorization_url, state = (
        current_app.oauth_client.generate_authorize_redirect(callback_uri)
    )
    flask.session['state'] = state
    return authorization_url


@blueprint.route('/authorize', methods=['GET'])
def do_authorize():
    """
    Send a token request to the OP.
    """
    callback_uri = current_app.config['HOSTNAME']
    try:
        assert flask.request.args['state'] == flask.session.pop('state')
    except (KeyError, AssertionError):
        raise AuthError('state did not match across auth requests')
    token = current_app.oauth_client.fetch_access_token(
        callback_uri,
        **flask.request.args
    )
    return token


@blueprint.route('/logout', methods=['GET'])
def logout_oauth():
    """
    Log out the user.
    """
    # TODO
    assert False
