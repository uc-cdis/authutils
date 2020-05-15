# pylint: disable=unused-argument

from collections import OrderedDict

import flask
import pytest
import httpx

from authutils.errors import JWTError, JWTAudienceError, JWTExpiredError
from authutils.token.keys import get_public_key
from authutils.token.core import validate_jwt
from authutils.token.validate import require_auth_header

from tests.utils import TEST_RESPONSE_JSON


def test_valid_signature(claims, encoded_jwt, rsa_public_key, default_audiences, iss):
    """
    Do a basic test of the expected functionality with the sample payload in
    the fence README.
    """
    decoded_token = validate_jwt(encoded_jwt, rsa_public_key, default_audiences, [iss])
    assert decoded_token
    assert decoded_token == claims


def test_expired_token_rejected(
    encoded_jwt_expired, rsa_public_key, default_audiences, iss
):
    with pytest.raises(JWTExpiredError):
        validate_jwt(encoded_jwt_expired, rsa_public_key, default_audiences, [iss])


def test_invalid_signature_rejected(
    encoded_jwt, rsa_public_key_2, default_audiences, iss
):
    """
    Test that ``validate_jwt`` rejects JWTs signed with a private key not
    corresponding to the public key it is given.
    """
    with pytest.raises(JWTError):
        validate_jwt(encoded_jwt, rsa_public_key_2, default_audiences, [iss])


def test_invalid_aud_rejected(encoded_jwt, rsa_public_key, iss):
    """
    Test that if ``validate_jwt`` is passed values for ``aud`` which do not
    appear in the token, a ``JWTAudienceError`` is raised.
    """
    with pytest.raises(JWTAudienceError):
        validate_jwt(encoded_jwt, rsa_public_key, {"not-in-aud"}, [iss])


def test_invalid_iss_rejected(encoded_jwt, rsa_public_key, iss):
    """
    Test that if ``validate_jwt`` receives a token whose value for ``iss``
    does not match the expected value, a ``JWTValidationError`` is raised.
    """
    wrong_iss = iss + "garbage"
    with pytest.raises(JWTError):
        validate_jwt(encoded_jwt, rsa_public_key, {"not-in-aud"}, [wrong_iss])


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


def test_validate_request_jwt_incorrect_usage(app, client, auth_header, mock_get):
    """
    Test that if a ``require_auth_header`` caller does not give it any
    audiences, a JWTAudienceError is raised.
    """
    mock_get()

    # This should raise a ValueError, since no audiences are provided.
    @require_auth_header({}, "access")
    def bad():
        return flask.jsonify({"foo": "bar"})

    app.add_url_rule("/test_incorrect_usage", "bad", bad)

    with pytest.raises(ValueError):
        client.get("/test_incorrect_usage", headers=auth_header)


def test_validate_request_jwt_missing(app, client, auth_header, mock_get):
    """
    Test that if the JWT is completely missing an audience which is required by
    an endpoint, a ``jwt.InvalidAudienceError`` is raised.
    """
    mock_get()

    # This should raise jwt.InvalidAudienceError, since the audience it
    # requires does not appear in the default JWT anywhere.
    @app.route("/test_missing_audience")
    @require_auth_header({"missing_audience"}, "access")
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTAudienceError):
        client.get("/test_missing_audience", headers=auth_header)


def test_validate_request_jwt_missing_some(app, client, auth_header, mock_get):
    """
    Test that if the JWT satisfies some audiences but is missing at least one
    audience which is required by an endpoint, a ``jwt.InvalidAudienceError``
    is raised.
    """
    mock_get()

    # This should raise JWTAudienceError, since the audience it requires does
    # not appear in the default JWT anywhere.
    @app.route("/test_missing_audience")
    @require_auth_header({"access", "missing_audience"}, "access")
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTAudienceError):
        client.get("/test_missing_audience", headers=auth_header)
