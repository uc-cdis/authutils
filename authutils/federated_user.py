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


class FederatedUser(object):

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
        self.hmac_keypair = hmac_keypair

        self._phsids = {}
        self.project_ids = {}
        self._roles = collections.defaultdict(set)
        self.role = None
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

    @cached_property
    def roles(self):
        return {
            project: role
            for phsid, roles in self.phsids.iteritems()
            for project in self.get_projects_mapping(phsid)
            for role in roles
        }

    @cached_property
    def phsids(self):
        return flask.current_app.auth.get_user_projects(self.user)

    def get_projects_mapping(self, phsid):
        if phsid in self.mapping:
            return self.mapping[phsid]
        with flask.current_app.db.session_scope():
            project = (
                flask.current_app
                .db
                .nodes(models.Project)
                .props(dbgap_accession_number=phsid)
                .first()
            )
            self.mapping[phsid] = []
            if project:
                self.mapping[phsid] = [
                    project.programs[0].name + '-' + project.code
                ]
            else:
                program = (
                    flask.current_app
                    .db
                    .nodes(models.Program)
                    .props(dbgap_accession_number=phsid)
                    .first()
                )
                if program:
                    self.mapping[phsid] = [
                        program.name + '-' + node.code
                        for node in program.projects
                    ]
        return self.mapping[phsid]

    def get_role_by_dbgap(self, dbgap_no):
        project = (
            flask_sqlalchemy_session.current_session
            .query(userdatamodel.user.Project)
            .filter(userdatamodel.user.Project.auth_id == dbgap_no)
            .first()
        )
        if not project:
            raise InternalError("Don't have project with {0}".format(dbgap_no))
        roles = (
            flask_sqlalchemy_session.current_session
            .query(AccessPrivilege)
            .filter(AccessPrivilege.user_id == flask.g.user.id)
            .filter(AccessPrivilege.project_id == project.id)
            .first()
        )
        if not roles:
            raise AuthError("You don't have access to the data")
        return roles

    def fetch_project_ids(self, role='_member_'):
        return [
            self.get_projects_mapping(phsid)
            for phsid, roles in self.phsids.iteritems()
            if role in roles
        ]

    def get_project_ids(self, role='_member_'):
        if role not in self.project_ids:
            self.project_ids[role] = self.fetch_project_ids(role)
        return self.project_ids[role]
