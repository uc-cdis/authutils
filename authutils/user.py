import functools
import json

from addict import Dict
from cached_property import cached_property
import flask
from userdatamodel.user import User

from authutils.token.validate import set_current_token, validate_request


class CurrentUser(object):
    """
    Args:
        aud (str): audiences required for validating the JWT
        claims (dict): claims from the user's token
        hmac_keypair (userdatamodel.user.HMACKeyPair): user's HMAC keypair
    """

    def __init__(self, aud='openid', claims=None):
        if not claims:
            claims = validate_request(aud=aud, purpose=None)

        self.claims = claims
        self.id = claims['sub']
        self.username = (
            claims
            .get('context', {})
            .get('user', {})
            .get('name', None)
        )
        self.projects = (
            self.claims
            .get('context', {})
            .get('user', {})
            .get('projects', [])
        )

        self.project_ids = {}
        self.mapping = {}

    def __str__(self):
        str_out = {
            'id': self.user.id,
            'username': self.user.username,
            'is_admin': self.user.is_admin
        }
        return json.dumps(str_out)

    @cached_property
    def user(self):
        """
        Return an ``addict.Dict`` (dictionary supporting access by attribute)
        containing the information from the SQLAlchemy model of this user.

        Requires flask app context.

        We return a ``Dict`` to avoid problems with the user model becoming
        detached from the original SQLAlchemy session.

        Return:
            addict.Dict: attributes on the user model
        """
        with flask.current_app.db.session as session:
            user = (
                session
                .query(User)
                .filter(User.id == self.claims['sub'])
                .first()
            )
            if not user:
                raise ValueError(
                    'no user exists with ID: {}'.format(self.claims['sub'])
                )
            return Dict(dict(user.__dict__))

    def get_project_ids(self, role='_member_'):
        """
        Return a list of projects for which the user has this role.
        """
        return [
            project
            for project, roles in self.projects.iteritems()
            if role in roles
        ]


def set_global_user(func):
    """
    Wrap a Flask blueprint view function to set the global user
    ``flask.g.user`` to an instance of ``CurrentUser``, according to the
    information from the JWT in the request headers. The validation will also
    set the current token.

    This requires a flask application and request context.
    """

    @functools.wraps(func)
    def f(*args, **kwargs):
        claims = validate_request(aud={'openid'}, purpose=None)
        set_current_token(claims)
        flask.g.user = CurrentUser(claims=claims)
        return func(*args, **kwargs)

    return f
