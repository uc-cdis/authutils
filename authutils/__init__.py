"""
Provides functions for handling user authentication and authorization.
"""

import functools

from authutils.errors import AuthError
from authutils.token.validate import get_auth_token_from_request
from authutils.token.validate import current_token
from authutils.token.utils import get_project_access
from authutils.token.utils import is_admin
from authutils.token.utils import get_username

from authutils.errors import JWTError

SERVICE = 'submission'
roles = dict(
    ADMIN='admin',
    CREATE='create',
    DELETE='delete',
    DOWNLOAD='download',
    GENERAL='_member_',
    READ='read',
    RELEASE='release',
    UPDATE='update',
)


def require_admin_auth_header(aud=None, purpose='access'):
    """
    Return a decorator which adds request validation to check if there is
    an auth token in the request and the given user is an admin
    """

    def decorator(f):
        """
        Decorate the given function to check for a valid JWT header with admin
        access
        """

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            """
            Wrap a function to first validate the request header token.

            Assign the claims from the token to ``flask.g._current_token`` so
            the code inside the function can use the ``LocalProxy`` for the
            token.

            Then check if the token has admin priveledges.
            """
            admin_auth(aud=aud, purpose=purpose)
            return f(*args, **kwargs)

        return wrapper

    return decorator

def admin_auth(aud=None, purpose='access'):
    aud = aud or ['openid']
    get_auth_token_from_request(aud=aud, purpose=purpose)
    if not is_admin(current_token):
        raise AuthError("You don't have admin access to perform this action")


def authorize_for_project(roles, aud=None, purpose='access'):
    """
    Wrap a flask blueprint route to do the following:

    #. Allow access to the handler iff the user has at least one of the roles
       requested on the given project
    #. Set the global variable `authutils.token.validate.current_token`
    #  to token from header.
    """
    def wrapper(func):
        @functools.wraps(func)
        def authorize_and_call(program, project, *args, **kwargs):
            aud = aud or ['openid']
            get_auth_token_from_request(aud=aud, purpose=purpose)
            project_id = '{}-{}'.format(program, project)
            project_access = get_project_access(current_token, project)

            # Get intersection of user's roles and requested roles
            if not set(project_access) & set(roles):
                raise AuthError(
                    role_error_msg(
                        get_username(current_token),
                        roles, project_id))
            return func(program, project, *args, **kwargs)
        return authorize_and_call
    return wrapper


def require_auth(aud=None, purpose='access'):
    """
    Check if a request is authenticated.
    """
    aud = aud or ['openid']
    try:
        get_auth_token_from_request(aud=aud, purpose=purpose)
    except JWTError:
        raise AuthError('This endpoint requires authentication')


def role_error_msg(user_name, roles, project):
    role_names = [
        role if role != '_member_' else 'read (_member_)' for role in roles
    ]
    return (
        "User {} doesn't have {} access in {}".format(
            user_name, ' or '.join(role_names), project
        )
    )
