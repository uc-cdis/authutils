"""
Stateless DPoP nonce management using shared symmetric HS256 JWTs.

The nonce is itself a JWT signed with a shared secret.
"""

import time
import os
from typing import Optional

from cdislogging import get_logger

from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.errors import BadSignatureError, InvalidPayloadError, JoseError

logging = get_logger(__name__)


def _get_shared_secret(secret: str | None = None) -> Optional[str]:
    """Get DPOP_SHARED_SECRET from environment (read at runtime for testability)."""
    return secret or os.getenv("DPOP_SHARED_SECRET")


def _get_nonce_ttl() -> int:
    """Get DPOP_NONCE_TTL from environment (read at runtime for testability)."""
    return int(os.getenv("DPOP_NONCE_TTL", "300"))


def generate_stateless_nonce(secret: str | None = None) -> str:
    """
    Mint a symmetric nonce token valid for DPOP_NONCE_TTL_SECONDS.

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

    Returns:
        bool: True if nonce is valid and within TTL, False otherwise.
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
            algorithms=["HS256"],
        )
        claims = token.claims

        now = int(time.time())
        iat = claims.get("iat")
        exp = claims.get("exp")

        if exp is not None and exp < now:
            return False

        if iat is not None and exp is not None and exp < iat:
            return False

        return claims.get("purpose") == "dpop_nonce"
    except (JoseError, TypeError, BadSignatureError, InvalidPayloadError) as exc:
        logging.debug(f"invalid nonce", exc_info=True)
        return False
    except Exception as exc:
        logging.exception(
            f"unknown error when attempting to verify nonce. Returning False / invalid."
        )
        return False
