from asyncio import Future, get_event_loop
from collections import OrderedDict

import httpx
from fastapi import Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.status import HTTP_403_FORBIDDEN

from . import core
from ..errors import JWTError, AuthError

bearer = HTTPBearer()

_jwt_public_keys = {}


def access_token(*audiences, issuer=None, allowed_issuers=None, purpose=None):
    """
    Validate and return the JWT bearer token in HTTP header::

        from fastapi import Depends

        @app.get("/whoami")
        def whoami(token=Depends(access_token("user", "openapi", purpose="access"))):
            return token["iss"]

    Args:
        *audiences: Required, all must occur in ``aud``.
        issuer: Force to use this issuer to validate the token if provided.
        allowed_issuers: Optional allowed issuers whitelist, default: allow all.
        purpose: Optional, must match ``pur`` if provided.

    Returns:
        Decoded JWT claims as a :class:`dict`.
    """

    if not audiences:
        raise ValueError("Missing parameter: audiences")
    audiences = set(audiences)
    if not allowed_issuers and issuer:
        allowed_issuers = [issuer]

    async def getter(token: HTTPAuthorizationCredentials = Security(bearer)):
        nonlocal issuer, allowed_issuers
        assert token.scheme.lower() == "bearer"
        token = token.credentials
        loop = get_event_loop()

        # get kid and issuer
        try:
            kid = await loop.run_in_executor(None, core.get_kid, token)
            if issuer is None:
                issuer = await loop.run_in_executor(None, core.get_iss, token)
        except JWTError as e:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Bad bearer token: " + str(e)
            )
        if not allowed_issuers:
            allowed_issuers = [issuer]
        if issuer not in allowed_issuers:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Bad bearer token: issuer is not allowed: " + issuer,
            )

        # get public key from cache, or fetch from issuer
        pub_keys = _jwt_public_keys.get(issuer)
        if not pub_keys:
            pub_keys = _jwt_public_keys[issuer] = Future()
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(core.get_keys_url(issuer))
                    resp.raise_for_status()
                    pub_keys.set_result(OrderedDict(resp.json()["keys"]))
            except Exception as e:
                _jwt_public_keys.pop(issuer)
                pub_keys.set_exception(
                    HTTPException(
                        status_code=HTTP_403_FORBIDDEN,
                        detail="Cannot fetch pubkey from issuer {}: {}".format(
                            issuer, str(e)
                        ),
                    )
                )
        pub_keys = await pub_keys
        pub_key = pub_keys.get(kid)
        if not pub_key:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Bad bearer token: kid not found in issuer: " + issuer,
            )

        # decode and validate the token
        try:
            claims = await loop.run_in_executor(
                None, core.validate_jwt, token, pub_key, audiences, allowed_issuers
            )

            if purpose:
                core.validate_purpose(claims, purpose)
        except AuthError as e:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Bad bearer token: " + str(e)
            )

        return claims

    return getter
