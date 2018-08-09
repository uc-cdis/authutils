from cdiserrors import AuthNError, AuthZError


class JWTError(AuthNError):

    pass


class JWTExpiredError(AuthNError):

    pass


class JWTPurposeError(JWTError):

    pass


class JWTAudienceError(JWTError):

    pass
