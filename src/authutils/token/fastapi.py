from asyncio import Future, get_event_loop
from collections import OrderedDict

import httpx2
from fastapi import Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.status import HTTP_403_FORBIDDEN

from . import core
from .keys import get_pem_key
from ..errors import JWTError, AuthError

bearer = HTTPBearer()

_jwt_public_keys = {}


def access_token(
    *scopes,
    audience=None,
    issuer=None,
    allowed_issuers=None,
    purpose=None,
    force_issuer=None
):
    """
    Validate and return the JWT bearer token in HTTP header::

        from fastapi import Depends

        @app.get("/whoami")
        def whoami(token=Depends(access_token("user", "openapi", purpose="access"))):
            return token["iss"]

    Args:
        *scopes: Required, all must occur in ``scope``.
        audience: Optional; if provided, JWT validation will require that the token's
          ``aud`` value contains the arg value; if not provided, validation will require
          that the token not have an aud field.
        issuer: Optional; force to use this issuer to validate the token if provided.
        allowed_issuers: Optional allowed issuers whitelist, default: allow all.
        purpose: Optional, must match ``pur`` if provided.
        force_issuer: Optional

    Returns:
        Decoded JWT claims as a :class:`dict`.
    """

    if not scopes:
        raise ValueError("Missing parameter: scopes")
    scopes = set(scopes)
    if not allowed_issuers and issuer:
        allowed_issuers = [issuer]

    async def getter(token: HTTPAuthorizationCredentials = Security(bearer)):
        assert token.scheme.lower() == "bearer"
        token = token.credentials
        loop = get_event_loop()

        # Per-request copies. These are derived from the incoming
        # token when the caller did not pin them, so persisting
        # would let the first request seen decide the issuer for every
        # later request -- one junk `iss` would 403 all subsequent valid tokens
        # for the life of the process.
        request_issuer = issuer
        request_allowed_issuers = allowed_issuers

        # get kid and issuer
        try:
            kid = await loop.run_in_executor(None, core.get_kid, token)
            if request_issuer is None:
                request_issuer = await loop.run_in_executor(None, core.get_iss, token)
        except JWTError as e:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Bad bearer token: " + str(e)
            )
        if not request_allowed_issuers:
            request_allowed_issuers = [request_issuer]
        if request_issuer not in request_allowed_issuers:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Bad bearer token: issuer is not allowed: " + request_issuer,
            )

        # get public key from cache, or fetch from issuer
        pub_keys = _jwt_public_keys.get(request_issuer)
        if not pub_keys:
            pub_keys = _jwt_public_keys[request_issuer] = Future()
            try:
                keys_url = await core.get_keys_url_async(request_issuer, force_issuer)
                async with httpx2.AsyncClient() as client:
                    resp = await client.get(keys_url)
                    resp.raise_for_status()
                    pub_keys.set_result(
                        OrderedDict(get_pem_key(key) for key in resp.json()["keys"])
                    )
            except Exception as e:
                _jwt_public_keys.pop(request_issuer)
                pub_keys.set_exception(
                    HTTPException(
                        status_code=HTTP_403_FORBIDDEN,
                        detail="Cannot fetch pubkey from issuer {}: {}".format(
                            request_issuer, str(e)
                        ),
                    )
                )
        pub_keys = await pub_keys
        pub_key = pub_keys.get(kid)
        if not pub_key:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Bad bearer token: kid not found in issuer: " + request_issuer,
            )

        # decode and validate the token
        try:
            claims = await loop.run_in_executor(
                None,
                core.validate_jwt,
                token,
                pub_key,
                audience,
                scopes,
                request_allowed_issuers,
            )

            if purpose:
                core.validate_purpose(claims, purpose)
        except AuthError as e:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Bad bearer token: " + str(e)
            )

        return claims

    return getter
