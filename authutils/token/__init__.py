import functools

import flask

# re-export
from authutils.token.validate import (
    current_token,
    set_current_token,
    store_session_token,
    get_session_token,
)
from authutils.errors import AuthError


__all__ = [
    'authorize_for_project',
    'current_token',
    'get_session_token',
    'set_current_token',
    'store_session_token',
]


def authorize_for_project(*roles):
    """
    Wrap a function to allow access to the handler iff the user has at least
    one of the roles requested on the given project.
    """

    def wrapper(func):

        @functools.wraps(func)
        def authorize_and_call(program, project, *args, **kwargs):
            project_id = '{}-{}'.format(program, project)
            # Get intersection of user's roles and requested roles
            # TODO: use token and not user
            project_roles = get_project_permissions()[project_id]
            if not project_roles & set(roles):
                raise AuthError(
                    _role_error_msg(flask.g.user.username, roles, project_id)
                )
            return func(program, project, *args, **kwargs)

        return authorize_and_call

    return wrapper


def _get_project_permissions():
    claims = validate_request(aud={'openid'}, purpose=None)
    return (
        claims
        .get('context', {})
        .get('user', {})
        .get('projects', {})
    )


def _role_error_msg(user_name, roles, project):
    role_names = [
        role if role != '_member_' else 'read (_member_)' for role in roles
    ]
    return (
        "User {} doesn't have {} access in {}".format(
            user_name, ' or '.join(role_names), project
        )
    )
