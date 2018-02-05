class AuthError(Exception):

    pass


class JWTError(AuthError):

    pass


class JWTPurposeError(JWTError):

    pass


class JWTAudienceError(JWTError):

    pass
