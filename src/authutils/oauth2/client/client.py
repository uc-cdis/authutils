# rename to maintain backwards compatibility
from authlib.integrations.flask_client import OAuth as OAuthClient


__all__ = ["OAuthClient"]
