from cdiserrors import AuthNError as CDISAuthNError


class InvalidNonceError(CDISAuthNError):
    """
    Base for the DPoP nonce errors, so a caller can catch either with one name.

    Both subclasses carry a freshly minted nonce for the client in
    `error_headers`; which one is raised depends only on whether the caller is
    an authorization server or a resource server. Declared here so that a caller
    catching this base can read the headers without narrowing to a subclass.
    """

    error_headers: dict[str, str]


class InvalidNonceErrorAuthorizationServer(InvalidNonceError):
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
        json: dict | None = None,
    ) -> None:
        """
        Build the error carrying a freshly minted nonce for the client.

        Args:
            new_nonce (str): Nonce to hand back in the DPoP-Nonce header.
            message (str): Error code per RFC 9449 8.
            code (int): HTTP status the authorization server should return.
            json (dict | None): Response body override. Defaults to the RFC
                9449 use_dpop_nonce body. Built per instance rather than as a
                default argument, so a caller mutating exc.json cannot alter
                every subsequent error.
        """
        super().__init__(
            message,
            code=code,
            json=(
                json
                if json is not None
                else {
                    "error": "use_dpop_nonce",
                    "error_description": "Authorization server requires nonce in DPoP proof",
                }
            ),
        )
        self.error_headers = {"DPoP-Nonce": new_nonce}


class InvalidNonceErrorResourceServer(InvalidNonceError):
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
        json: dict | None = None,
    ) -> None:
        """
        Build the error carrying a freshly minted nonce for the client.

        Args:
            new_nonce (str): Nonce to hand back in the DPoP-Nonce header.
            message (str): Error code per RFC 9449 8.
            code (int): HTTP status the resource server should return.
            json (dict | None): Response body override. Defaults to the RFC
                9449 use_dpop_nonce body. Built per instance rather than as a
                default argument, so a caller mutating exc.json cannot alter
                every subsequent error.
        """
        super().__init__(
            message,
            code=code,
            json=(
                json
                if json is not None
                else {
                    "error": "use_dpop_nonce",
                    "error_description": "Resource server requires nonce in DPoP proof",
                }
            ),
        )
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
