from cdiserrors import AuthNError as CDISAuthNError


class InvalidNonceErrorAuthorizationServer(CDISAuthNError):
    """
    Handle DPoP Nonce per the spec RFC9449.

    This error contains the necessary information for an
    Authorization server to
    return an error specifying a new nonce to the client (in not
    provided one or nonce provided is invalid).
    """

    def __init__(
        self,
        new_nonce: str,
        message: str = "use_dpop_nonce",
        code: int = 400,
        json: dict = {
            "error": "use_dpop_nonce",
            "error_description": "Authorization server requires nonce in DPoP proof",
        },
    ):
        super().__init__(message, code=code, json=json)
        self.error_headers = {"DPoP-Nonce": new_nonce}


class InvalidNonceErrorResourceServer(CDISAuthNError):
    """
    Handle DPoP Nonce per the spec RFC9449.

    This error contains the necessary information for a
    Resource Server to
    return an error specifying a new nonce to the client (in not
    provided one or nonce provided is invalid).
    """

    def __init__(
        self,
        new_nonce: str,
        message: str = "use_dpop_nonce",
        code: int = 401,
        json: dict = {
            "error": "use_dpop_nonce",
            "error_description": "Authorization server requires nonce in DPoP proof",
        },
    ):
        super().__init__(message, code=code, json=json)
        self.error_headers = {
            "DPoP-Nonce": new_nonce,
            "WWW-Authenticate": 'DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"',
        }


class AuthError(CDISAuthNError):

    pass


class JWTError(AuthError):

    pass


class JWTExpiredError(AuthError):

    pass


class JWTPurposeError(JWTError):

    pass


class JWTAudienceError(JWTError):

    pass


class JWTScopeError(JWTError):

    pass
