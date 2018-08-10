"""authutils.federated_user"""


import collections
import json

from cached_property import cached_property
from cdiserrors import (
    AuthError,
    InternalError,
    InvalidTokenError,
)
from datamodelutils import models
import flask
import flask_sqlalchemy_session
import userdatamodel
from userdatamodel.user import AccessPrivilege, User

from authutils.token.validate import validate_request


class CurrentUser(object):
    """
    Args:
        aud (str): audiences required for validating the JWT
        claims (dict): claims from the user's token
        hmac_keypair (userdatamodel.user.HMACKeyPair): user's HMAC keypair
    """

    def __init__(self, aud='openid', claims=None, hmac_keypair=None):
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
        self.hmac_keypair = hmac_keypair

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
        Return the SQLAlchemy model of this user.

        Requires flask app context.

        Return:
            userdatamodel.user.User
        """
        with flask.current_app.db.session as session:
            return (
                session
                .query(User)
                .filter(User.id == self.claims['sub'])
                .first()
            )

    def get_project_ids(self, role='_member_'):
        """
        Return a list of projects for which the user has this role.
        """
        return [
            project
            for project, roles in self.projects.iteritems()
            if role in roles
        ]
