# pylint: disable=unused-argument

from collections import OrderedDict
import jwt

import flask
import pytest
import httpx

from authutils.errors import JWTError, JWTAudienceError, JWTExpiredError, JWTScopeError
from authutils.token.keys import get_public_key
from authutils.token.core import validate_jwt
from authutils.token.validate import require_auth_header

from tests.utils import TEST_RESPONSE_JSON


def test_valid_signature(
    claims, encoded_jwt, rsa_public_key, default_audiences, default_scopes, iss
):
    """
    Do a basic test of the expected functionality with the sample payload in
    the fence README.
    """
    decoded_token = validate_jwt(
        encoded_jwt, rsa_public_key, default_audiences, default_scopes, [iss]
    )
    assert decoded_token
    assert decoded_token == claims


def test_expired_token_rejected(
    encoded_jwt_expired, rsa_public_key, default_audiences, default_scopes, iss
):
    with pytest.raises(JWTExpiredError):
        validate_jwt(
            encoded_jwt_expired,
            rsa_public_key,
            default_audiences,
            default_scopes,
            [iss],
        )


def test_invalid_signature_rejected(
    encoded_jwt, rsa_public_key_2, default_audiences, default_scopes, iss
):
    """
    Test that ``validate_jwt`` rejects JWTs signed with a private key not
    corresponding to the public key it is given.
    """
    with pytest.raises(JWTError):
        validate_jwt(
            encoded_jwt, rsa_public_key_2, default_audiences, default_scopes, [iss]
        )


def test_invalid_scope_rejected(encoded_jwt, rsa_public_key, default_audiences, iss):
    """
    Test that if ``validate_jwt`` is passed values for ``scope`` which do not
    appear in the token, a ``JWTScopeError`` is raised.
    """
    with pytest.raises(JWTScopeError):
        validate_jwt(
            encoded_jwt, rsa_public_key, default_audiences, {"not-in-scopes"}, [iss]
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
    encoded_jwt, rsa_public_key, default_audiences, default_scopes, iss
):
    """
    Test that if ``validate_jwt`` receives a token whose value for ``iss``
    does not match the expected value, a ``JWTValidationError`` is raised.
    """
    wrong_iss = iss + "garbage"
    with pytest.raises(JWTError):
        validate_jwt(
            encoded_jwt, rsa_public_key, default_audiences, default_scopes, [wrong_iss]
        )


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
    httpx.get.assert_called_once()
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


def test_validate_request_jwt_missing_all_scopes(app, client, auth_header, mock_get):
    """
    Test that if the JWT is completely missing a scope which is required by
    an endpoint, a ``JWTScopeError`` is raised.
    """
    mock_get()

    # This should raise a JWTScopeError, since the scope it
    # requires does not appear in the default JWT anywhere.
    @app.route("/test_missing_scope")
    @require_auth_header({"missing_scope"}, "access")
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTScopeError):
        client.get("/test_missing_scope", headers=auth_header)


def test_validate_request_jwt_missing_some_scopes(app, client, auth_header, mock_get):
    """
    Test that if the JWT satisfies some scopes but is missing at least one
    scope which is required by an endpoint, a ``JWTScopeError``
    is raised.
    """
    mock_get()

    # This should raise JWTScopeError, since the scope it requires does
    # not appear in the default JWT anywhere.
    @app.route("/test_missing_scope")
    @require_auth_header({"access", "missing_scope"}, "access")
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTScopeError):
        client.get("/test_missing_scope", headers=auth_header)
