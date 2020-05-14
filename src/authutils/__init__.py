from authutils.errors import AuthError

try:
    from authutils.user import CurrentUser, set_global_user
except ImportError:
    CurrentUser = set_global_user = None

__all__ = ["AuthError", "CurrentUser", "ROLES", "set_global_user"]

ROLES = dict(
    ADMIN="admin",
    CREATE="create",
    DELETE="delete",
    DOWNLOAD="download",
    GENERAL="_member_",
    READ="read",
    RELEASE="release",
    UPDATE="update",
)
