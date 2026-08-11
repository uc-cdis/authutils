# pylint: disable=unused-argument

from collections import OrderedDict
import jwt

import flask
import pytest
import httpx2

from authutils.errors import JWTError, JWTAudienceError, JWTExpiredError, JWTScopeError
from authutils.token.keys import get_public_key
from authutils.token.core import validate_jwt
from authutils.token.validate import require_auth_header

from tests.utils import TEST_RESPONSE_JSON


def test_valid_signature(
    claims, encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Do a basic test of the expected functionality with the sample payload in
    the fence README.
    """
    decoded_token = validate_jwt(
        encoded_jwt, rsa_public_key, default_audience, default_scopes, [iss]
    )
    assert decoded_token
    assert decoded_token == claims


def test_expired_token_rejected(
    encoded_jwt_expired, rsa_public_key, default_audience, default_scopes, iss
):
    with pytest.raises(JWTExpiredError):
        validate_jwt(
            encoded_jwt_expired,
            rsa_public_key,
            default_audience,
            default_scopes,
            [iss],
        )


def test_invalid_signature_rejected(
    encoded_jwt, rsa_public_key_2, default_audience, default_scopes, iss
):
    """
    Test that ``validate_jwt`` rejects JWTs signed with a private key not
    corresponding to the public key it is given.
    """
    with pytest.raises(JWTError):
        validate_jwt(
            encoded_jwt, rsa_public_key_2, default_audience, default_scopes, [iss]
        )


def test_invalid_scope_rejected(encoded_jwt, rsa_public_key, default_audience, iss):
    """
    Test that if ``validate_jwt`` is passed values for ``scope`` which do not
    appear in the token, a ``JWTScopeError`` is raised.
    """
    with pytest.raises(JWTScopeError):
        validate_jwt(
            encoded_jwt, rsa_public_key, default_audience, {"not-in-scopes"}, [iss]
        )


def test_missing_aud_rejected(encoded_jwt, rsa_public_key, default_scopes, iss):
    """
    Test that if ``validate_jwt`` is passed a value for ``aud`` which does not
    appear in the token, a ``JWTError`` is raised.
    """
    with pytest.raises(JWTError):
        validate_jwt(encoded_jwt, rsa_public_key, "not-in-aud", default_scopes, [iss])


def test_unexpected_aud_rejected(
    encoded_jwt,
    rsa_public_key,
    default_scopes,
    iss,
):
    """
    Test that if the token contains an ``aud`` claim and no ``aud`` arg is passed
    to ``validate_jwt``, a ``JWTAudienceError`` is raised.
    """
    with pytest.raises(JWTAudienceError):
        validate_jwt(encoded_jwt, rsa_public_key, None, default_scopes, [iss])


def test_expected_missing_aud_accepted(
    claims,
    token_headers,
    rsa_private_key,
    rsa_public_key,
    default_scopes,
    iss,
):
    """
    Test that if no ``aud`` arg is passed to ``validate_jwt`` and the token does NOT
    contain an ``aud`` claim then validation passes.
    """
    claims = claims.copy()
    claims.pop("aud")
    encoded_token = jwt.encode(
        claims, headers=token_headers, key=rsa_private_key, algorithm="RS256"
    )
    validate_jwt(encoded_token, rsa_public_key, None, default_scopes, [iss])


def test_valid_aud_accepted(
    claims, token_headers, rsa_private_key, rsa_public_key, default_scopes, iss
):
    """
    Test that if the token contains multiple audience values in its ``aud`` claim
    and one of those values is passed to ``validate_jwt`` then validation passes.
    """
    claims = claims.copy()
    claims["aud"] = ["foo", "bar", "baz"]
    encoded_token = jwt.encode(
        claims, headers=token_headers, key=rsa_private_key, algorithm="RS256"
    )
    validate_jwt(encoded_token, rsa_public_key, "baz", default_scopes, [iss])


def test_invalid_iss_rejected(
    encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Test that if ``validate_jwt`` receives a token whose value for ``iss``
    does not match the expected value, a ``JWTValidationError`` is raised.
    """
    wrong_iss = iss + "garbage"
    with pytest.raises(JWTError):
        validate_jwt(
            encoded_jwt, rsa_public_key, default_audience, default_scopes, [wrong_iss]
        )


def test_token_without_iss_rejected_as_jwt_error(
    claims, token_headers, rsa_private_key, rsa_public_key, default_audience, iss
):
    """
    A token carrying no iss at all raises JWTError, not KeyError.

    A caller doing `except JWTError: return 401` would otherwise emit a 500 for
    an attacker-supplied token that simply omits the claim.
    """
    claims_without_iss = {k: v for k, v in claims.items() if k != "iss"}
    encoded = jwt.encode(
        claims_without_iss,
        headers=token_headers,
        key=rsa_private_key,
        algorithm="RS256",
    )

    with pytest.raises(JWTError):
        validate_jwt(
            encoded,
            rsa_public_key,
            aud=default_audience,
            allowed_issuers=[iss],
        )


def test_denylist_callback_rejects_token(
    claims, encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Test that `validate_jwt` rejects tokens when denylist_callback returns True.
    """

    def denylist_callback(jti):
        # Deny all tokens for this test
        return True

    with pytest.raises(JWTError) as exc_info:
        validate_jwt(
            encoded_jwt,
            rsa_public_key,
            default_audience,
            default_scopes,
            [iss],
            denylist_callback=denylist_callback,
        )


def test_denylist_callback_allows_token(
    claims, encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Test that `validate_jwt` accepts tokens when denylist_callback returns False.
    """

    def allowlist_callback(jti):
        # Allow all tokens for this test
        return False

    decoded_token = validate_jwt(
        encoded_jwt,
        rsa_public_key,
        default_audience,
        default_scopes,
        [iss],
        denylist_callback=allowlist_callback,
    )
    assert decoded_token
    assert decoded_token == claims


def test_denylist_callback_receives_jti(
    claims,
    token_headers,
    rsa_private_key,
    rsa_public_key,
    default_audience,
    default_scopes,
    iss,
):
    """
    Test that denylist_callback receives the correct jti value.
    """
    received_jti = None

    def callback(jti):
        nonlocal received_jti
        received_jti = jti
        return False

    claims_with_jti = claims.copy()
    claims_with_jti["jti"] = "test-jti-123"

    encoded_token = jwt.encode(
        claims_with_jti,
        headers=token_headers,
        key=rsa_private_key,
        algorithm="RS256",
    )
    # Verify that callback is called with values from the token
    decoded = validate_jwt(
        encoded_token,
        rsa_public_key,
        default_audience,
        default_scopes,
        [iss],
        denylist_callback=callback,
    )
    # Check that callback was called with values from the token
    assert received_jti == claims_with_jti["jti"]


def test_denylist_callback_not_callable_raises_value_error(
    encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Test that `validate_jwt` raises ValueError if denylist_callback is not callable.
    """
    with pytest.raises(ValueError):
        validate_jwt(
            encoded_jwt,
            rsa_public_key,
            default_audience,
            default_scopes,
            [iss],
            denylist_callback="not_callable",
        )


def test_validate_jwt_with_purpose(
    claims, encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Test that `validate_jwt` validates purpose when provided.
    """
    # Token should have correct purpose
    decoded_token = validate_jwt(
        encoded_jwt,
        rsa_public_key,
        default_audience,
        default_scopes,
        [iss],
        purpose="access",
    )
    assert decoded_token == claims


def test_validate_jwt_with_incorrect_purpose(
    claims, encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Test that `validate_jwt` rejects tokens with incorrect purpose.
    """
    with pytest.raises(JWTError):
        validate_jwt(
            encoded_jwt,
            rsa_public_key,
            default_audience,
            default_scopes,
            [iss],
            purpose="refresh",
        )


def test_validate_jwt_without_purpose(
    claims, encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Test that `validate_jwt` works without purpose parameter (None skips validation).
    """
    decoded_token = validate_jwt(
        encoded_jwt,
        rsa_public_key,
        default_audience,
        default_scopes,
        [iss],
        purpose=None,
    )
    assert decoded_token == claims


def test_validate_jwt_with_scope_as_list(
    claims, encoded_jwt, rsa_public_key, default_audience, iss
):
    """
    Test that `validate_jwt` accepts scope as list and converts to set internally.
    """
    decoded_token = validate_jwt(
        encoded_jwt,
        rsa_public_key,
        default_audience,
        # scope as list - using scopes from the token
        ["user", "openid"],
        [iss],
    )
    assert decoded_token == claims


def test_validate_jwt_with_options(
    claims, encoded_jwt, rsa_public_key, default_audience, default_scopes, iss
):
    """
    Test that `validate_jwt` passes options through to PyJWT.
    """
    decoded_token = validate_jwt(
        encoded_jwt,
        rsa_public_key,
        "bad_aud",
        default_scopes,
        [iss],
        options={"verify_aud": False},
    )
    assert decoded_token == claims


def test_validate_jwt_type_validation():
    """
    Test that `validate_jwt` validates argument types.
    """
    with pytest.raises(ValueError):
        validate_jwt(
            "token", "key", aud=123, scope=None, allowed_issuers=[]
        )  # aud must be str/list/None


def test_get_public_key(app, example_keys_response, mock_get):
    """
    Test the functionality of retrieving the public keys from the keys
    endpoint.
    """
    mock_get()
    test_kid, expected_key = example_keys_response["keys"][0]
    iss = app.config["USER_API"]
    expected_jwt_public_keys_dict = {iss: OrderedDict(example_keys_response["keys"])}
    key = get_public_key(kid=test_kid)
    # httpx2.get should be called twice: once attempting to get the jwks_uri from
    # .well-known/openid-configuration, another to actually hit the jwks_uri
    assert httpx2.get.call_count == 2
    assert key
    assert key == expected_key
    assert app.jwt_public_keys == expected_jwt_public_keys_dict


def test_get_nonexistent_public_key_fails(app, mock_get):
    """
    Test that if there is no key found for the provided key id, a
    JWTValidationError is raised.
    """
    mock_get()
    with pytest.raises(JWTError):
        get_public_key(kid="nonsense")


def test_validate_request_jwt(client, auth_header, mock_get):
    """
    Test that a request including a valid JWT works.
    """
    mock_get()
    response = client.get("/test", headers=auth_header)
    assert response.status_code == 200
    assert response.json == TEST_RESPONSE_JSON


def test_validate_request_no_jwt_fails(client, mock_get):
    """
    Test that if no authorization header is included, a JWTValidationError is
    raised.
    """
    mock_get()
    with pytest.raises(JWTError):
        client.get("/test")


def test_validate_request_jwt_bad_header(client, mock_get, encoded_jwt):
    mock_get()
    incorrect_headers = {"Authorization": encoded_jwt}
    with pytest.raises(JWTError):
        client.get("/test", headers=incorrect_headers)


def test_validate_request_jwt_missing_all_scopes(
    app, client, auth_header, default_audience, mock_get
):
    """
    Test that if the JWT is completely missing a scope which is required by
    an endpoint, a ``JWTScopeError`` is raised.
    """
    mock_get()

    # This should raise a JWTScopeError, since the scope it
    # requires does not appear in the default JWT anywhere.
    @app.route("/test_missing_scope")
    @require_auth_header({"missing_scope"}, default_audience, "access")
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTScopeError):
        client.get("/test_missing_scope", headers=auth_header)


def test_validate_request_jwt_missing_some_scopes(
    app, client, auth_header, default_audience, mock_get
):
    """
    Test that if the JWT satisfies some scopes but is missing at least one
    scope which is required by an endpoint, a ``JWTScopeError``
    is raised.
    """
    mock_get()

    # This should raise JWTScopeError, since the scope it requires does
    # not appear in the default JWT anywhere.
    @app.route("/test_missing_scope")
    @require_auth_header({"access", "missing_scope"}, default_audience, "access")
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTScopeError):
        client.get("/test_missing_scope", headers=auth_header)
