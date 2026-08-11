import fastapi
import jwt
import pytest
from starlette.testclient import TestClient

from authutils.token.fastapi import access_token


@pytest.fixture(scope="function")
def async_client(default_scopes, default_audience, mock_async_get, iss):
    mock_async_get()

    app = fastapi.FastAPI()

    @app.get("/whoami")
    def whoami(
        token=fastapi.Depends(
            access_token(*default_scopes, audience=default_audience, purpose="access")
        )
    ):
        return token

    @app.get("/force_issuer")
    def force_issuer(
        token=fastapi.Depends(
            access_token(
                *default_scopes, audience=default_audience, issuer=iss, purpose="access"
            )
        )
    ):
        return token

    @app.get("/whitelist")
    def whitelist(
        token=fastapi.Depends(
            access_token(
                *default_scopes,
                allowed_issuers=["https://right.example.com"],
                purpose="access",
            )
        )
    ):
        return token

    with TestClient(app) as client:
        yield client


def test_no_scopes():
    with pytest.raises(ValueError, match="scopes"):
        access_token()


def test_no_header(async_client):
    """
    Test 40x response when no header is provided at all.

    Note: Different versions of FastAPI have different response status codes.
          We really just want to verify it's one of them.

    https://fastapi.tiangolo.com/how-to/authentication-error-status-code/#use-old-403-authentication-error-status-codes
    """
    assert async_client.get("/whoami").status_code in {403, 401}


def test_no_issuers_whitelist(auth_header, async_client, claims):
    resp = async_client.get("/whoami", headers=dict(auth_header))
    assert resp.status_code == 200
    assert resp.json() == claims


def test_force_issuer(auth_header, async_client, claims):
    resp = async_client.get("/force_issuer", headers=dict(auth_header))
    assert resp.status_code == 200
    assert resp.json() == claims


def test_force_issuer_wrong_issuer(
    async_client, claims, token_headers, rsa_private_key
):
    claims = claims.copy()
    claims["iss"] = "https://wrong.example.com"
    token = jwt.encode(
        claims, headers=token_headers, key=rsa_private_key, algorithm="RS256"
    )
    headers = {"Authorization": "Bearer {}".format(token)}
    assert async_client.get("/force_issuer", headers=headers).status_code == 403


def test_issuers_whitelist(auth_header, async_client):
    assert async_client.get("/whitelist", headers=dict(auth_header)).status_code == 403


def test_rejected_token_does_not_poison_later_requests(
    async_client, auth_header, claims, token_headers, rsa_private_key
):
    """
    Regression Test for authutils.token.fastapi.access_token()

    A rejected token must not affect the next request's issuer resolution.

    The issuer is derived from the incoming token whenever the caller did not
    pin one. Previously, the iss value was cached to a global, so the
    first request seen would decide the issuer for every later request, and a
    single unauthenticated junk `iss` would 403 all subsequent valid tokens for
    the life of the process.
    """
    bad_claims = claims.copy()
    bad_claims["iss"] = "https://attacker.example.com"
    bad_token = jwt.encode(
        bad_claims, headers=token_headers, key=rsa_private_key, algorithm="RS256"
    )

    assert (
        async_client.get(
            "/whoami", headers={"Authorization": f"Bearer {bad_token}"}
        ).status_code
        == 403
    )

    assert async_client.get("/whoami", headers=dict(auth_header)).status_code == 200


def test_bad_token(async_client, auth_header):
    headers = {k: v[:-5] for k, v in auth_header}
    assert async_client.get("/whoami", headers=headers).status_code == 403


def test_wrong_issuer(async_client, claims, token_headers, rsa_private_key):
    claims = claims.copy()
    claims["iss"] = "https://wrong.example.com"
    token = jwt.encode(
        claims, headers=token_headers, key=rsa_private_key, algorithm="RS256"
    )
    headers = {"Authorization": "Bearer {}".format(token)}
    assert async_client.get("/whoami", headers=headers).status_code == 403


def test_wrong_kid(async_client, claims, token_headers, rsa_private_key):
    token_headers = token_headers.copy()
    token_headers["kid"] = "nonexist"
    token = jwt.encode(
        claims, headers=token_headers, key=rsa_private_key, algorithm="RS256"
    )
    headers = {"Authorization": "Bearer {}".format(token)}
    assert async_client.get("/whoami", headers=headers).status_code == 403


def test_expired(async_client, claims, encoded_jwt, encoded_jwt_expired):
    headers = {"Authorization": "Bearer {}".format(encoded_jwt)}
    resp = async_client.get("/whoami", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == claims

    headers = {"Authorization": "Bearer {}".format(encoded_jwt_expired)}
    assert async_client.get("/whoami", headers=headers).status_code == 403
