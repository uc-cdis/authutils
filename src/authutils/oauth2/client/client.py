# rename to maintain backwards compatibility
from authlib.oauth2.client import OAuth2Client as OAuthClient


__all__ = ["OAuthClient"]
