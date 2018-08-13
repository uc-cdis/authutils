import functools
import json

from addict import Dict
from cached_property import cached_property
import flask
from userdatamodel.user import User
from werkzeug.local import LocalProxy

from authutils.errors import AuthError
from authutils.token.validate import set_current_token, validate_request


def _get_or_set_current_user(**kwargs):
    if not hasattr(flask.g, 'user'):
        flask.g.user = CurrentUser(**kwargs)
        set_current_token(flask.g.user.claims)
    return flask.g.user


# Proxy for the current user.
#
# Other modules importing authutils can import ``current_user`` from here,
# which will use ``_get_or_set_current_user`` to look up the user.
current_user = LocalProxy(_get_or_set_current_user)


class CurrentUser(object):
    """
    Args:
        claims (dict): claims from the user's token (if validated already)
        app_get_session (Function[[flask.Flask], sqlalchemy.orm.Session]):
            how to get db session context on flask app
        jwt_kwargs (dict): keyword arguments to pass to ``validate_request``

    Attributes:
        claims (dict): dictionary of claims from user token
        id (str): unique ID for the user
        projects (Dict[str, List[str]): mapping of project IDs to roles
    """

    def __init__(self, claims=None, app_get_session=None, jwt_kwargs=None):
        self.get_session = app_get_session or (lambda app: app.db.session)
        jwt_kwargs = jwt_kwargs or {}
        if 'aud' not in jwt_kwargs:
            jwt_kwargs['aud'] = {'openid'}
        self.claims = claims or validate_request(**jwt_kwargs)
        self.id = self.claims['sub']
        self.username = self._get_user_info('name')
        self.projects = self._get_user_info('projects', default={})
        self.mapping = {}

    def __str__(self):
        str_out = {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
        }
        return json.dumps(str_out)

    def _get_user_info(self, field, default=None):
        return (
            self.claims
            .get('context', {})
            .get('user', {})
            .get(field, default)
        )

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
        with self.get_session(flask.current_app) as session:
            user = session.query(User).filter(User.id == self.id).first()
            if not user:
                raise ValueError('no user exists with ID: {}'.format(self.id))
            return Dict(dict(user.__dict__))

    @cached_property
    def is_admin(self):
        """
        Indicate whether the current user has admin privileges.

        Return:
            bool: whether user is admin
        """
        # Try to just use the user context from the claims. If that doesn't
        # have the ``is_admin`` field then use the database lookup.
        if self._get_user_info('is_admin') is not None:
            return self._get_user_info('is_admin')
        else:
            return getattr(self.user, 'is_admin')

    def require_admin(self):
        """
        Raise an error if this user doesn't have admin privileges.
        """
        if not self.is_admin:
            raise AuthError(
                'user ({}) does not have admin privileges'
                .format(self.id)
            )

    def reload_user(self):
        """
        Reset the cached user property and redo the database lookup for this
        user.

        Return:
            userdatamodel.models.User
        """
        del self.__dict__['user']
        return self.user

    def get_project_ids(self, role='_member_'):
        """
        Return a list of projects for which the user has this role.
        """
        return [
            project
            for project, roles in self.projects.iteritems()
            if role in roles
        ]


def set_global_user(**decorator_kwargs):
    """
    Wrap a Flask blueprint view function to set the global user
    ``flask.g.user`` to an instance of ``CurrentUser``, according to the
    information from the JWT in the request headers. The validation will also
    set the current token.

    This requires a flask application and request context.
    """

    def decorator(func):

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            _get_or_set_current_user(**decorator_kwargs)
            return func(*args, **kwargs)

        return wrapper

    return decorator
