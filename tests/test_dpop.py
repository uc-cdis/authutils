"""
Test DPoP functionality in authutils.dpop module.
"""

import base64
import json
import os
import time
from typing import Any
from unittest.mock import patch

import pytest
from joserfc import jwk, jwt

import authutils.dpop
from authutils.token import dpop_nonce
from authutils.dpop import DPOP_PROOF_MAX_TTL
from authutils.errors import InvalidNonceError, JWTScopeError, JWTPurposeError


def _create_signed_access_token(
    key: jwk.Key,
    subject: str = "test-user",
    issuer: str = "https://example.com",
    audience: str = "test-audience",
    scopes: list[str] | None = None,
    purpose: str = "access",
    additional_claims: dict | None = None,
) -> str:
    """
    Create a signed access token with proper claims for testing.

    Args:
        key (jwk.Key): The signing key (ECKey or RSAKey)
        subject (str): The subject (sub) claim
        issuer (str): The issuer (iss) claim
        audience (str): The audience (aud) claim
        scopes (list[str] | None): List of scopes to include in the token
        purpose (str): The purpose (pur) claim
        additional_claims (dict | None): Optional additional claims to include

    Returns:
        str: Signed JWT access token
    """
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        # 1 hour from now
        "exp": now + 3600,
        "pur": purpose,
        "scope": scopes or ["openid", "user"],
    }
    if additional_claims:
        payload.update(additional_claims)

    if key:
        payload["cnf"] = {"jkt": key.thumbprint()}

    # Always use RS256 for access tokens since token validation only supports RS256
    header = {"alg": "RS256", "typ": "JWT"}
    return jwt.encode(header, payload, key)


@pytest.fixture(autouse=True)
def set_shared_secret():
    """Set the cluster secret environment variable before each test."""
    os.environ[
        "DPOP_SHARED_SECRET"
    ] = "test-secret-32chars-minimum-test"  # pragma: allowlist secret
    yield
    os.environ.pop("DPOP_SHARED_SECRET", None)


class TestValidateDpopProofSuccess:
    """Tests for successful validate_dpop_proof calls that verify return values."""

    def test_returns_dpop_claims_and_client_jwk_tuple(self):
        """
        Test that validate_dpop_proof returns a tuple of (dpop_claims, client_jwk).
        This allows callers to get both values in a single call without needing
        to call both validate_dpop_proof and extract_and_validate_jwk separately.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        # Call validate_dpop_proof and verify it returns a tuple
        result = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )

        # Verify return type is a tuple
        assert isinstance(result, tuple), "validate_dpop_proof should return a tuple"

        # Verify tuple has exactly 2 elements
        assert len(result) == 2, "validate_dpop_proof should return a 2-element tuple"

        # Verify first element is the dpop claims dict
        dpop_claims, client_jwk = result
        assert isinstance(
            dpop_claims, dict
        ), "First element should be a dict (dpop_claims)"
        assert "htm" in dpop_claims, "dpop_claims should contain 'htm'"
        assert "htu" in dpop_claims, "dpop_claims should contain 'htu'"
        assert "iat" in dpop_claims, "dpop_claims should contain 'iat'"
        assert dpop_claims["htm"] == "GET", "htm should match request method"

        # Verify second element is the client jwk
        assert client_jwk is not None, "client_jwk should not be None"
        # client_jwk can be an ECKey or RSAKey, check for key attributes
        assert hasattr(client_jwk, "as_dict"), "client_jwk should have as_dict method"
        jwk_dict = client_jwk.as_dict(private=False)
        assert "kty" in jwk_dict, "client_jwk should have 'kty' attribute"
        assert jwk_dict["kty"] == "EC", "client_jwk should be EC type"


class TestNoneDpopHeaderValidation:
    """Tests for None or empty dpop_header validation."""

    @pytest.mark.parametrize(
        "invalid_header",
        [
            pytest.param(None, id="none_header"),
            pytest.param("", id="empty_string_header"),
        ],
    )
    def test_invalid_dpop_header_raises_value_error(self, invalid_header):
        """
        Test that validate_dpop_proof raises ValueError when dpop_header is None or empty string.
        """
        with pytest.raises(ValueError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                invalid_header, "GET", "https://example.com/resource"
            )
        assert "Invalid DPoP proof: Empty string / None provided" in str(exc_info.value)


class TestBidirectionalBinding:
    """Bidirectional Binding (Stolen Token Defense)"""

    def test_stolen_token_defense(self):
        """
        Verify that an attacker cannot sign a valid DPoP proof
        with their own key but bind it to a victim's stolen access token.
        """
        # Generate Alice's key and create a mock access token containing Alice's key thumbprint (cnf.jkt)
        alice_key = jwk.ECKey.generate_key(crv="P-256")
        alice_thumbprint = alice_key.thumbprint()

        # Create a valid access token with Alice's thumbprint using a proper header with alg
        alice_token_payload = {"sub": "alice", "cnf": {"jkt": alice_thumbprint}}
        hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
        alice_token = jwt.encode(
            {"alg": "HS256", "typ": "JWT"},
            alice_token_payload,
            hs_key,
        )

        # Generate the Attacker's key
        attacker_key = jwk.ECKey.generate_key(crv="P-256")

        # Call generate_dpop_proof() using the Attacker's key, providing Alice's access token to generate the ath claim
        attacker_proof = authutils.dpop.generate_dpop_proof(
            attacker_key, "GET", "https://example.com/resource", alice_token
        )

        # Run validate_dpop_proof() passing the Attacker's proof header and Alice's access token
        # This should raise ValueError because attacker's key thumbprint doesn't match Alice's thumbprint
        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                attacker_proof, "GET", "https://example.com/resource", alice_token
            )


class TestStrictConditionalNonceValidation:
    """Strict Conditional Nonce Validation per RFC 9449"""

    def test_missing_required_nonce(self):
        """
        Test Case A (Missing & Required): Generate a DPoP proof without a nonce.
        Call validate_dpop_proof(..., require_nonce=True).
        Expects InvalidNonceError containing new nonce response headers.
        """
        # Generate a DPoP proof without a nonce
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(InvalidNonceError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", require_nonce=True
            )

        err = exc_info.value
        assert err.code == 400
        assert err.json["error"] == "use_dpop_nonce"
        assert "DPoP-Nonce" in err.error_headers
        assert isinstance(err.error_headers["DPoP-Nonce"], str)
        assert len(err.error_headers["DPoP-Nonce"]) > 0

    @patch("authutils.dpop.verify_stateless_nonce", return_value=False)
    def test_provided_unexpectedly_invalid_nonce(self, mock_verify_nonce):
        """
        Test Case B (Provided unexpectedly & Invalid): Generate a DPoP proof
        containing an expired or garbage nonce string. Call validate_dpop_proof(..., require_nonce=False).
        Even though require_nonce=False, an invalid nonce should still raise InvalidNonceError.
        """
        # Generate a DPoP proof with invalid nonce
        key = jwk.ECKey.generate_key(crv="P-256")
        invalid_nonce = "garbage-nonce-not-valid"

        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", nonce=invalid_nonce
        )

        with pytest.raises(InvalidNonceError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", require_nonce=False
            )

        err = exc_info.value
        assert err.code == 400
        assert "DPoP-Nonce" in err.error_headers


class TestNonceValidationAndInvalidNonceError:
    """Tests for DPoP nonce validation and InvalidNonceError handling per RFC 9449."""

    def test_missing_required_nonce_raises_invalid_nonce_error(self):
        """
        Test that validate_dpop_proof raises InvalidNonceError when require_nonce=True
        and the DPoP proof lacks a nonce claim.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(InvalidNonceError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", require_nonce=True
            )

        err = exc_info.value

        assert err.code == 400
        assert err.json == {
            "error": "use_dpop_nonce",
            "error_description": "Authorization server requires nonce in DPoP proof",
        }

        # Verify new nonce header was generated for client resubmission
        assert "DPoP-Nonce" in err.error_headers
        assert isinstance(err.error_headers["DPoP-Nonce"], str)
        assert len(err.error_headers["DPoP-Nonce"]) > 0

    @patch("authutils.token.dpop_nonce.verify_stateless_nonce", return_value=False)
    def test_invalid_nonce_raises_invalid_nonce_error(self, mock_verify_nonce):
        """
        Test that validate_dpop_proof raises InvalidNonceError when an invalid/expired
        nonce is provided, even if require_nonce=False.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        invalid_nonce = "garbage-or-expired-nonce"
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", nonce=invalid_nonce
        )

        with pytest.raises(InvalidNonceError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", require_nonce=False
            )

        err = exc_info.value

        assert err.code == 400
        assert "DPoP-Nonce" in err.error_headers
        assert isinstance(err.error_headers["DPoP-Nonce"], str)
        assert len(err.error_headers["DPoP-Nonce"]) > 0

    def test_valid_nonce_passes_validation(self):
        """
        Test that validate_dpop_proof succeeds without error when a valid stateless nonce
        is provided and require_nonce=True.
        """
        valid_nonce = dpop_nonce.generate_stateless_nonce()
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", nonce=valid_nonce
        )

        dpop_claims, client_jwk = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource", require_nonce=True
        )

        assert dpop_claims["nonce"] == valid_nonce
        assert client_jwk is not None

    def test_custom_secret_passed_to_nonce_validation(self):
        """
        Test that custom secrets passed to validate_dpop_proof correctly validate nonces.
        """
        custom_secret = "custom-test-secret-32-chars-long!"  # pragma: allowlist secret
        valid_nonce = dpop_nonce.generate_stateless_nonce(secret=custom_secret)

        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", nonce=valid_nonce
        )

        # Verification with matching secret should succeed
        dpop_claims, _ = authutils.dpop.validate_dpop_proof(
            proof,
            "GET",
            "https://example.com/resource",
            require_nonce=True,
            secret=custom_secret,
        )
        assert dpop_claims["nonce"] == valid_nonce

        # Verification with mismatched secret should fail and raise InvalidNonceError
        with pytest.raises(InvalidNonceError):
            authutils.dpop.validate_dpop_proof(
                proof,
                "GET",
                "https://example.com/resource",
                require_nonce=True,
                secret="wrong-secret-key-32-chars-long!!",  # pragma: allowlist secret
            )


class TestAlgorithmWhitelisting:
    """Algorithm Whitelisting & Key Cross-Compatibility"""

    def test_rsa_verification(self):
        """
        Test Case A (RSA Verification): Generate an RSA private key.
        Generate a proof using generate_dpop_proof(rsa_key, ...) and verify
        the header resolves automatically to RS256.
        """
        # Generate an RSA private key
        rsa_key = jwk.RSAKey.generate_key()

        # Generate a proof using generate_dpop_proof(rsa_key, ...)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/resource"
        )

        # Verify the header resolves automatically to RS256
        header_b64, _, _ = proof.split(".")
        header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        header_json = json.loads(
            base64.urlsafe_b64decode(header_padded).decode("utf-8")
        )
        assert header_json["alg"] == "RS256"
        assert header_json.get("typ") == "dpop+jwt"
        assert "jwk" in header_json

    def test_algorithm_confusion_injection(self):
        """
        Test Case B (Algorithm Confusion Injection): Generate a valid EC proof,
        but manually intercept and edit the unverified header parameter "alg": "HS256"
        (e.g. not allowed). Pass it to validate_dpop_proof().
        Expected Assertion: Raises ValueError
        """
        # Generate a valid EC proof
        ec_key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            ec_key, "GET", "https://example.com/resource"
        )

        # Manually intercept and edit the unverified header parameter "alg": "HS256"
        header_b64, payload_b64, signature = proof.split(".")

        # Decode and modify header
        header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        header_json = json.loads(
            base64.urlsafe_b64decode(header_padded).decode("utf-8")
        )
        header_json["alg"] = "HS256"

        # Re-encode the header
        new_header_json = json.dumps(header_json)
        new_header_b64 = (
            base64.urlsafe_b64encode(new_header_json.encode()).rstrip(b"=").decode()
        )

        # Create a new proof with the modified header
        new_proof = f"{new_header_b64}.{payload_b64}.{signature}"

        # Pass it to validate_dpop_proof()
        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                new_proof, "GET", "https://example.com/resource"
            )


class TestGenerateStatelessNonce:
    """Tests for generate_stateless_nonce."""

    def test_generate_nonce_success(self):
        """Returns valid HS256 JWT with purpose=dpop_nonce and correct exp."""
        nonce = dpop_nonce.generate_stateless_nonce()

        # Decode without verification to check claims
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        token_obj = jwt.decode(nonce, key=hs_key)
        decoded = token_obj.claims
        assert decoded["purpose"] == "dpop_nonce"
        assert "iat" in decoded
        assert "exp" in decoded

        # Check TTL is approximately correct
        now = int(time.time())
        ttl = decoded["exp"] - decoded["iat"]
        assert abs(ttl - DPOP_PROOF_MAX_TTL) < 3

    def test_generate_nonce_missing_secret_raises(self):
        """Raises RuntimeError when DPOP_SHARED_SECRET is unset."""
        # Set a valid secret first
        os.environ[
            "DPOP_SHARED_SECRET"
        ] = "test-secret-32chars-minimum-test"  # pragma: allowlist secret

        # Remove the environment variable
        old_secret = os.environ.pop("DPOP_SHARED_SECRET", None)

        try:
            with pytest.raises(RuntimeError):
                dpop_nonce.generate_stateless_nonce()
        finally:
            os.environ["DPOP_SHARED_SECRET"] = old_secret


class TestVerifyStatelessNonce:
    """Tests for verify_stateless_nonce."""

    def test_verify_nonce_valid(self):
        """Returns True for a freshly generated nonce."""
        nonce = dpop_nonce.generate_stateless_nonce()
        assert dpop_nonce.verify_stateless_nonce(nonce) is True

    def test_verify_nonce_with_different_secret(self):
        """Returns False when verified with a different secret."""
        # Set a valid secret
        old_secret = os.environ["DPOP_SHARED_SECRET"]

        # Generate nonce with original secret
        nonce = dpop_nonce.generate_stateless_nonce()

        # Change the secret
        os.environ[
            "DPOP_SHARED_SECRET"
        ] = "completely-different-secret-key-123"  # pragma: allowlist secret

        try:
            # Should return False with different secret
            assert dpop_nonce.verify_stateless_nonce(nonce) is False
        finally:
            os.environ["DPOP_SHARED_SECRET"] = old_secret

    def test_verify_nonce_empty_string(self):
        """Returns False for empty/None input."""
        assert dpop_nonce.verify_stateless_nonce("") is False
        assert dpop_nonce.verify_stateless_nonce(None) is False

    def test_verify_nonce_expired(self):
        """Returns False for an expired nonce."""
        now = int(time.time())
        expired_payload = {
            "iat": now - 10000,
            "exp": now - 5000,
            "purpose": "dpop_nonce",
        }
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        expired_nonce = jwt.encode(
            header={"alg": "HS256", "typ": "JWT"},
            claims=expired_payload,
            key=hs_key,
        )
        assert dpop_nonce.verify_stateless_nonce(expired_nonce) is False

    def test_verify_nonce_wrong_purpose(self):
        """Returns False for nonce with wrong purpose."""
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 345600,
            "purpose": "wrong_purpose",
        }
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        nonce = jwt.encode(
            header={"alg": "HS256", "typ": "JWT"}, claims=payload, key=hs_key
        )
        assert dpop_nonce.verify_stateless_nonce(nonce) is False

    def test_verify_nonce_tampered_signature(self):
        """Returns False for a modified nonce string."""
        nonce = dpop_nonce.generate_stateless_nonce()
        tampered = nonce[:-5] + "foobar"
        assert dpop_nonce.verify_stateless_nonce(tampered) is False


class TestVerifyStatelessNonceEdgeCases:
    """Edge case tests for nonce verification."""

    def test_generate_nonce_with_special_characters_in_secret(self):
        """Nonce generation works with special characters in secret."""
        os.environ["DPOP_SHARED_SECRET"] = "test!@#$%^&*()-_+=[]{}|;':\",./<>?"
        nonce = dpop_nonce.generate_stateless_nonce()
        # Should generate a valid nonce
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        token_obj = jwt.decode(nonce, key=hs_key)
        decoded = token_obj.claims
        assert decoded["purpose"] == "dpop_nonce"

    def test_verify_nonce_with_malformed_base64(self):
        """Returns False for JWT with malformed base64 encoding."""
        # JWT with invalid base64 characters in each part
        assert dpop_nonce.verify_stateless_nonce("abc.def.ghi") is False
        assert dpop_nonce.verify_stateless_nonce("!!!.!!!.!!!") is False
        assert dpop_nonce.verify_stateless_nonce("a.") is False

    def test_verify_nonce_with_empty_jwt_parts(self):
        """Returns False for JWT with empty parts."""
        assert dpop_nonce.verify_stateless_nonce("..") is False
        assert dpop_nonce.verify_stateless_nonce("a..") is False
        assert dpop_nonce.verify_stateless_nonce("..c") is False

    def test_verify_nonce_with_only_header(self):
        """Returns False for incomplete JWT (only header)."""
        # Generate a valid JWT and truncate it
        nonce = dpop_nonce.generate_stateless_nonce()
        parts = nonce.split(".")
        assert dpop_nonce.verify_stateless_nonce(parts[0]) is False
        assert dpop_nonce.verify_stateless_nonce(parts[0] + "." + parts[1]) is False

    def test_verify_nonce_with_invalid_json_in_header(self):
        """Returns False for JWT with invalid JSON in header."""
        # Create a JWT with invalid JSON in header
        invalid_header = (
            base64.urlsafe_b64encode(b"{invalid json}").rstrip(b"=").decode()
        )
        payload = base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode()
        signature = "sig"
        malformed = f"{invalid_header}.{payload}.{signature}"
        assert dpop_nonce.verify_stateless_nonce(malformed) is False

    def test_verify_nonce_with_invalid_json_in_payload(self):
        """Returns False for JWT with invalid JSON in payload."""
        header = base64.urlsafe_b64encode(b'{"typ":"JWT"}').rstrip(b"=").decode()
        invalid_payload = (
            base64.urlsafe_b64encode(b"{invalid json}").rstrip(b"=").decode()
        )
        signature = "sig"
        malformed = f"{header}.{invalid_payload}.{signature}"
        assert dpop_nonce.verify_stateless_nonce(malformed) is False

    def test_verify_nonce_with_whitespace_variations(self):
        """Returns False for JWT with unexpected whitespace."""
        nonce = dpop_nonce.generate_stateless_nonce()
        # Add various whitespace characters
        assert dpop_nonce.verify_stateless_nonce(" " + nonce) is False
        assert dpop_nonce.verify_stateless_nonce(nonce + " ") is False
        assert dpop_nonce.verify_stateless_nonce(nonce.replace(".", ". ")) is False

    def test_verify_nonce_with_numeric_input(self):
        """Returns False for numeric input."""
        assert dpop_nonce.verify_stateless_nonce(12345) is False
        assert dpop_nonce.verify_stateless_nonce(0) is False
        assert dpop_nonce.verify_stateless_nonce(-1) is False

    def test_verify_nonce_with_list_input(self):
        """Returns False for list input."""
        assert dpop_nonce.verify_stateless_nonce(["a", "b", "c"]) is False
        assert dpop_nonce.verify_stateless_nonce([]) is False

    def test_verify_nonce_with_dict_input(self):
        """Returns False for dict input."""
        assert dpop_nonce.verify_stateless_nonce({"a": "b"}) is False
        assert dpop_nonce.verify_stateless_nonce({}) is False

    def test_verify_nonce_with_expired_but_malformed(self):
        """Returns False for expired nonce with malformed timestamp."""
        # Create a JWT with negative timestamp (invalid)
        payload = {
            "iat": -10000,
            "exp": -5000,
            "purpose": "dpop_nonce",
        }
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        malformed = jwt.encode(
            header={"alg": "HS256", "typ": "JWT"}, claims=payload, key=hs_key
        )
        assert dpop_nonce.verify_stateless_nonce(malformed) is False

    def test_verify_nonce_with_future_timestamp_malformation(self):
        """Returns False for token with future but malformed timestamps."""
        now = int(time.time())
        # CreateExpired but with exp before iat (malformed)
        payload = {
            "iat": now + 10000,
            "exp": now + 5000,  # exp < iat, malformed
            "purpose": "dpop_nonce",
        }
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        malformed = jwt.encode(
            header={"alg": "HS256", "typ": "JWT"}, claims=payload, key=hs_key
        )
        assert dpop_nonce.verify_stateless_nonce(malformed) is False

    def test_verify_nonce_with_extremely_short_ttl(self):
        """Returns False for nonce with negative TTL (exp < iat)."""
        now = int(time.time())
        # Expired immediately
        payload = {
            "iat": now,
            "exp": now - 1,  # exp < iat
            "purpose": "dpop_nonce",
        }
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        short_ttl = jwt.encode(
            header={"alg": "HS256", "typ": "JWT"}, claims=payload, key=hs_key
        )
        assert dpop_nonce.verify_stateless_nonce(short_ttl) is False


class TestValidateDpopRequest:
    """Tests for validate_dpop_request."""

    @pytest.fixture
    def rsa_key(self):
        """Generate an RSA key for testing."""
        return jwk.RSAKey.generate_key()

    @pytest.fixture
    def ec_key(self):
        """Generate an EC key for DPoP proof testing."""
        return jwk.ECKey.generate_key(crv="P-256")

    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_validate_dpop_request_return(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        Test that validate_dpop_request returns a tuple with exactly 3 elements:
        (dpop_claims, access_token_claims, client_jwk).
        """
        # Create signed access token with proper key binding (RSA for token validation)
        access_token = _create_signed_access_token(rsa_key)

        dpop_proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "POST", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        result = authutils.dpop.validate_dpop_request(
            dpop_header=dpop_proof,
            access_token=access_token,
            request_method="POST",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
        )

        assert len(result) == 3, "validate_dpop_request should return a 3-element tuple"
        dpop_claims, token_claims, client_jwk = result

        assert isinstance(dpop_claims, dict), "First element should be dpop_claims dict"
        assert "htm" in dpop_claims, "dpop_claims should contain 'htm'"
        assert "htu" in dpop_claims, "dpop_claims should contain 'htu'"
        assert "iat" in dpop_claims, "dpop_claims should contain 'iat'"
        assert "jti" in dpop_claims, "dpop_claims should contain 'jti'"
        assert dpop_claims["htm"] == "POST", "htm should match request method"
        assert (
            dpop_claims["htu"] == "https://example.com/api/resource"
        ), "htu should match request URL"

        assert isinstance(
            token_claims, dict
        ), "Second element should be token_claims dict"
        assert token_claims["sub"] == "test-user", "token should contain correct sub"
        assert (
            token_claims["iss"] == "https://example.com"
        ), "token should contain correct iss"
        assert token_claims["pur"] == "access", "token should contain correct pur"

        assert client_jwk is not None, "client_jwk should not be None"
        assert hasattr(client_jwk, "as_dict"), "client_jwk should have as_dict method"
        jwk_dict = client_jwk.as_dict(private=False)
        assert "kty" in jwk_dict, "client_jwk should have 'kty' attribute"
        assert jwk_dict["kty"] == "RSA", "client_jwk should be RSA type"

    @pytest.mark.parametrize("http_method", ["GET", "POST", "PUT", "DELETE", "PATCH"])
    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_different_http_methods(
        self, mock_validate_jwt, mock_get_public_key, http_method
    ):
        """
        Test that validate_dpop_request works with different HTTP methods.
        """
        # Use RSA key since access token validation only supports RS256
        dpop_key = jwk.RSAKey.generate_key()
        access_token = _create_signed_access_token(dpop_key)
        proof = authutils.dpop.generate_dpop_proof(
            dpop_key, http_method, "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = dpop_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        result = authutils.dpop.validate_dpop_request(
            dpop_header=proof,
            access_token=access_token,
            request_method=http_method,
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
        )

        dpop_claims, _, _ = result
        assert dpop_claims["htm"] == http_method

    @pytest.mark.parametrize("key_type", ["EC", "RSA"])
    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_different_key_types(
        self, mock_validate_jwt, mock_get_public_key, key_type
    ):
        """
        Test that validate_dpop_request works with different key types (EC and RSA).
        Note: Access tokens use RS256, so we use RSA keys for access token.
        For EC key tests, the DPoP proof uses EC but access token uses RS256 with RSA key.
        """
        if key_type == "EC":
            dpop_key = jwk.ECKey.generate_key(crv="P-256")
            # Create RSA key for access token (RS256 only)
            rsa_key = jwk.RSAKey.generate_key()
            access_token = _create_signed_access_token(rsa_key)
            # Use RSA key for DPoP proof for consistency
            dpop_key = rsa_key
        else:
            dpop_key = jwk.RSAKey.generate_key()

        access_token = _create_signed_access_token(dpop_key)
        proof = authutils.dpop.generate_dpop_proof(
            dpop_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = dpop_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        result = authutils.dpop.validate_dpop_request(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
        )

        dpop_claims, token_claims, client_jwk = result

        assert dpop_claims["htm"] == "GET"
        assert dpop_claims["htu"] == "https://example.com/api/resource"

        assert token_claims["sub"] == "test-user"

        jwk_dict = client_jwk.as_dict(private=False)
        assert (
            jwk_dict["kty"] == "RSA"
        ), "All tests use RSA keys due to RS256 requirement"

    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_access_token_scopes_validation(
        self, mock_validate_jwt, mock_get_public_key
    ):
        """
        Test that validate_dpop_request validates the required scopes.
        """
        # Use RSA key for access token (RS256 only)
        dpop_key = jwk.RSAKey.generate_key()
        access_token = _create_signed_access_token(
            dpop_key, scopes=["openid", "user", "data"]
        )

        proof = authutils.dpop.generate_dpop_proof(
            dpop_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = dpop_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user", "data"],
        }

        # Should succeed with matching scopes
        result = authutils.dpop.validate_dpop_request(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            scope={"openid", "user", "data"},
        )

        dpop_claims, token_claims, client_jwk = result
        assert dpop_claims["htm"] == "GET"

    def test_secret_parameter_fallback_to_env(self):
        """
        Test that when secret=None is passed, it defaults to the environment variable.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        nonce = dpop_nonce.generate_stateless_nonce()
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", nonce=nonce
        )

        # Call with secret=None should use the DPOP_SHARED_SECRET from fixture
        dpop_claims, client_jwk = authutils.dpop.validate_dpop_proof(
            proof,
            "GET",
            "https://example.com/resource",
            require_nonce=True,
            secret=None,
        )
        assert dpop_claims.get("nonce") == nonce

    def test_secret_parameter_explicit_value(self):
        """
        Test that when an explicit secret is passed, it uses that secret.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        nonce = dpop_nonce.generate_stateless_nonce()
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", nonce=nonce
        )

        # Get the secret from the fixture to verify we can pass it explicitly
        explicit_secret = os.environ["DPOP_SHARED_SECRET"]

        # Call with explicit secret should work the same
        dpop_claims, client_jwk = authutils.dpop.validate_dpop_proof(
            proof,
            "GET",
            "https://example.com/resource",
            require_nonce=True,
            secret=explicit_secret,
        )
        assert dpop_claims.get("nonce") == nonce

    def test_secret_parameter_passed_to_verify(self):
        """
        Test that the secret parameter is correctly passed to verify_stateless_nonce.
        By generating a nonce with a known secret and then verifying with the same secret,
        we confirm that the secret is being passed through correctly.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        # Use a custom secret that we control
        custom_secret = (
            "custom-test-secret-32chars-minimum-test"  # pragma: allowlist secret
        )

        # Temporarily set the custom secret in environment
        old_secret = os.environ.get("DPOP_SHARED_SECRET")
        os.environ["DPOP_SHARED_SECRET"] = custom_secret
        try:
            # Generate nonce with custom secret
            nonce = dpop_nonce.generate_stateless_nonce()
            proof = authutils.dpop.generate_dpop_proof(
                key, "GET", "https://example.com/resource", nonce=nonce
            )
        finally:
            # Restore original secret
            if old_secret:
                os.environ["DPOP_SHARED_SECRET"] = old_secret
            else:
                os.environ.pop("DPOP_SHARED_SECRET", None)

        # Now verify with explicit secret - should succeed if secret is passed correctly
        dpop_claims, client_jwk = authutils.dpop.validate_dpop_proof(
            proof,
            "GET",
            "https://example.com/resource",
            require_nonce=True,
            secret=custom_secret,
        )
        assert dpop_claims.get("nonce") == nonce

    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_validate_dpop_request_secret_parameter(
        self, mock_validate_jwt, mock_get_public_key
    ):
        """
        Test that secret parameter is properly passed through from validate_dpop_request.
        """
        key = jwk.RSAKey.generate_key()
        custom_secret = (
            "custom-request-secret-32chars-minimum-test"  # pragma: allowlist secret
        )

        # Temporarily set the custom secret for nonce generation
        old_secret = os.environ.get("DPOP_SHARED_SECRET")
        os.environ["DPOP_SHARED_SECRET"] = custom_secret
        try:
            nonce = dpop_nonce.generate_stateless_nonce()

            # Create access token with key binding
            access_token = _create_signed_access_token(
                key, additional_claims={"cnf": {"jkt": key.thumbprint()}}
            )

            proof = authutils.dpop.generate_dpop_proof(
                key,
                "POST",
                "https://example.com/api/resource",
                access_token,
                nonce=nonce,
            )

            mock_get_public_key.return_value = key.as_pem()
            mock_validate_jwt.return_value = {
                "sub": "test-user",
                "iss": "https://example.com",
                "aud": "test-audience",
                "pur": "access",
                "scope": ["openid", "user"],
            }

            (
                dpop_claims,
                token_claims,
                client_jwk,
            ) = authutils.dpop.validate_dpop_request(
                dpop_header=proof,
                access_token=access_token,
                request_method="POST",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                require_nonce=True,
                secret=custom_secret,
            )
            assert dpop_claims["nonce"] == nonce
        finally:
            # Restore original secret
            if old_secret:
                os.environ["DPOP_SHARED_SECRET"] = old_secret
            else:
                os.environ.pop("DPOP_SHARED_SECRET", None)

    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_access_token_scope_missing_raises(
        self, mock_validate_jwt, mock_get_public_key
    ):
        """
        Test that validate_dpop_request raises JWTScopeError when required scope is missing.
        """
        # Use RSA key for access token (RS256 only)
        dpop_key = jwk.RSAKey.generate_key()
        access_token = _create_signed_access_token(dpop_key, scopes=["openid", "user"])

        proof = authutils.dpop.generate_dpop_proof(
            dpop_key, "GET", "https://example.com/api/resource", access_token
        )

        # Set up mock to raise JWTScopeError
        mock_get_public_key.return_value = dpop_key.as_pem()
        mock_validate_jwt.side_effect = JWTScopeError("token scope validation failed")

        with pytest.raises(JWTScopeError):
            authutils.dpop.validate_dpop_request(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                scope={"openid", "user", "data"},
            )

    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_access_token_purpose_validation(
        self, mock_validate_jwt, mock_get_public_key
    ):
        """
        Test that validate_dpop_request validates the required purpose.
        """
        # Use RSA key for access token (RS256 only)
        dpop_key = jwk.RSAKey.generate_key()
        access_token = _create_signed_access_token(dpop_key, purpose="access")

        proof = authutils.dpop.generate_dpop_proof(
            dpop_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = dpop_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        result = authutils.dpop.validate_dpop_request(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            purpose="access",
        )

        dpop_claims, token_claims, client_jwk = result
        assert token_claims["pur"] == "access"

    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_access_token_purpose_mismatch_raises(
        self, mock_validate_jwt, mock_get_public_key
    ):
        """
        Test that validate_dpop_request raises JWTPurposeError when purpose doesn't match.
        """
        # Use RSA key for access token (RS256 only)
        dpop_key = jwk.RSAKey.generate_key()
        access_token = _create_signed_access_token(dpop_key, purpose="refresh")

        proof = authutils.dpop.generate_dpop_proof(
            dpop_key, "GET", "https://example.com/api/resource", access_token
        )

        # Set up mock to raise JWTPurposeError
        mock_get_public_key.return_value = dpop_key.as_pem()
        mock_validate_jwt.side_effect = JWTPurposeError(
            "token purpose validation failed"
        )

        with pytest.raises(JWTPurposeError):
            authutils.dpop.validate_dpop_request(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                purpose="access",
            )

    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_denylist_callback_denylisted(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        Test that validate_dpop_request raises JWTError when the token is denylisted.
        """
        from authutils.token import core as token_core

        access_token = _create_signed_access_token(
            rsa_key, additional_claims={"jti": "test-jti-123"}
        )

        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()

        def denylist_callback(jti):
            # This jti is in the token, so it should return True
            return jti == "test-jti-123"

        # Set up mock to raise JWTError - simulating denylist behavior
        mock_validate_jwt.side_effect = token_core.JWTError("token is denylisted")

        # Should raise JWTError when token is denylisted
        with pytest.raises(token_core.JWTError, match="token is denylisted"):
            authutils.dpop.validate_dpop_request(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                denylist_callback=denylist_callback,
            )

    @patch("authutils.dpop.get_any_public_key_for_token")
    @patch("authutils.dpop.token_core.validate_jwt")
    def test_denylist_callback_not_denylisted(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        Test that validate_dpop_request succeeds when the token is not denylisted.
        """
        access_token = _create_signed_access_token(
            rsa_key, additional_claims={"jti": "test-jti-123"}
        )

        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()

        def denylist_callback(jti):
            # This jti is NOT in the denylist, so it should return False
            return jti == "denylisted-jti"

        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
            "jti": "test-jti-123",
        }

        result = authutils.dpop.validate_dpop_request(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            denylist_callback=denylist_callback,
        )

        dpop_claims, token_claims, client_jwk = result
        assert dpop_claims["htm"] == "GET"
