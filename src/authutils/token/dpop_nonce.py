"""
Stateless DPoP nonce management using shared symmetric HS256 JWTs.

The nonce is itself a JWT signed with a shared secret.
"""

import time
import os

from cdislogging import get_logger

from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.errors import JoseError

logging = get_logger(__name__)


def generate_stateless_nonce(secret: str | None = None) -> str:
    """
    Mint a symmetric nonce token valid for DPOP_NONCE_TTL seconds.

    Returns:
        str: HS256-signed JWT nonce token.

    Raises:
        RuntimeError: If DPOP_SHARED_SECRET environment variable not set.
    """
    shared_secret = _get_shared_secret(secret=secret)
    if not shared_secret:
        raise RuntimeError("DPOP_SHARED_SECRET environment variable not set")

    iat: int = int(time.time())
    exp: int = iat + _get_nonce_ttl()

    claims: dict = {
        "iat": iat,
        "exp": exp,
        "purpose": "dpop_nonce",
    }
    header: dict = {"alg": "HS256"}
    key = OctKey.import_key(shared_secret)
    return jwt.encode(header, claims, key)


def verify_stateless_nonce(client_nonce: str, secret: str | None = None) -> bool:
    """
    Verify nonce originated from this cluster and hasn't expired.

    Args:
        client_nonce (str): Nonce token to verify.
        secret (str | None): Shared secret. Defaults to DPOP_SHARED_SECRET.

    Returns:
        bool: True if nonce is valid and within TTL, False otherwise. Never
        raises: every failure mode, including an unexpected one, is reported
        as an invalid nonce.
    """
    if not isinstance(client_nonce, str):
        return False

    shared_secret = _get_shared_secret(secret=secret)
    if not client_nonce or not shared_secret:
        return False

    try:
        key = OctKey.import_key(shared_secret)
        token = jwt.decode(
            client_nonce,
            key,
            # This symetric alg uses secret key for both signing and verifying,
            # so only parties with the shared key can validate.
            algorithms=["HS256"],
        )
        claims = token.claims

        now = int(time.time())
        iat = claims.get("iat")
        exp = claims.get("exp")

        # exp is required, not just checked when present
        if exp is None or exp < now:
            return False

        if iat is not None and exp < iat:
            return False

        return claims.get("purpose") == "dpop_nonce"
    except (JoseError, TypeError):
        # BadSignatureError and InvalidPayloadError are JoseError subclasses.
        logging.debug("invalid nonce", exc_info=True)
        return False
    except Exception:
        logging.exception(
            "unknown error when attempting to verify nonce. Returning False / invalid."
        )
        return False


def _get_shared_secret(secret: str | None = None) -> str | None:
    """Get DPOP_SHARED_SECRET from environment (read at runtime for testability)."""
    return secret or os.getenv("DPOP_SHARED_SECRET")


def _get_nonce_ttl() -> int:
    """Get DPOP_NONCE_TTL from environment (read at runtime for testability)."""
    return int(os.getenv("DPOP_NONCE_TTL", "300"))
