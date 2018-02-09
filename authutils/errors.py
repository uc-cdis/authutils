from cdiserrors import AuthError as CDISAuthError


class AuthError(CDISAuthError):

    pass


class JWTError(AuthError):

    pass


class JWTPurposeError(JWTError):

    pass


class JWTAudienceError(JWTError):

    pass
