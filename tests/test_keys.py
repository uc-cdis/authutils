"""
Unit tests for authutils.token.keys module, specifically
for `get_any_public_key_for_token`
"""

import time
from unittest.mock import Mock, patch

import pytest
from joserfc import jwk, jwt

import authutils.token.keys as keys_module
from authutils.errors import JWTError


class TestGetAnyPublicKeyForToken:
    """Tests for get_any_public_key_for_token function."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear the cache before and after each test."""
        keys_module._token_public_key_cache.clear()
        yield
        keys_module._token_public_key_cache.clear()

    @pytest.fixture
    def mock_rsa_key(self):
        """Create a mock RSA key for testing."""
        return {
            "kty": "RSA",
            "kid": "test-key-id",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",  # pragma: allowlist secret
            "e": "AQAB",
        }

    @pytest.fixture
    def mock_jwks_response(self, mock_rsa_key):
        """Create a mock JWKS response."""
        return {"keys": [mock_rsa_key]}

    @pytest.fixture
    def valid_token(self):
        """Create a valid JWT token for testing."""
        hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
        payload = {
            "iss": "https://example.com/issuer",
            "sub": "test-user",
            "kid": "test-key-id",
        }
        header = {"alg": "HS256", "typ": "JWT", "kid": "test-key-id"}
        return jwt.encode(header, payload, hs_key)

    @patch("authutils.token.keys.get_keys_url")
    @patch("authutils.token.keys.httpx.get")
    def test_successful_key_retrieval(
        self, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test successful retrieval of a public key from a valid token."""
        mock_get_keys_url.return_value = (
            "https://example.com/issuer/.well-known/jwks.json"
        )
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_get.return_value = mock_response

        # First call should fetch from network
        result = keys_module.get_any_public_key_for_token(valid_token)

        assert result is not None
        assert isinstance(result, (str, bytes))
        mock_get.assert_called_once()

    @patch("authutils.token.keys.get_keys_url")
    @patch("authutils.token.keys.httpx.get")
    def test_cache_hit(
        self, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test that cache returns the same key on second call."""
        mock_get_keys_url.return_value = (
            "https://example.com/issuer/.well-known/jwks.json"
        )
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_get.return_value = mock_response

        # First call
        result1 = keys_module.get_any_public_key_for_token(valid_token)
        # Second call
        result2 = keys_module.get_any_public_key_for_token(valid_token)

        # Should have only called httpx.get once (second call was cached)
        assert mock_get.call_count == 1
        assert result1 == result2

    @patch("authutils.token.keys.get_keys_url")
    @patch("authutils.token.keys.httpx.get")
    @patch("authutils.token.keys.time.time")
    def test_cache_expiration(
        self, mock_time, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test that cache entries expire after TTL."""
        mock_get_keys_url.return_value = (
            "https://example.com/issuer/.well-known/jwks.json"
        )
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_get.return_value = mock_response

        # Mock time progression
        current_time = 1000.0
        mock_time.side_effect = [
            # First cache write
            current_time,
            # First cache check (hit)
            current_time,
            # Second cache check (expired)
            current_time + 400,
            # Second cache write (after expiration)
            current_time + 400,
        ]

        # First call
        result1 = keys_module.get_any_public_key_for_token(valid_token, cache_ttl=300)

        # Second call within TTL (should be cached)
        result2 = keys_module.get_any_public_key_for_token(valid_token, cache_ttl=300)

        # Third call after TTL (should fetch again)
        result3 = keys_module.get_any_public_key_for_token(valid_token, cache_ttl=300)

        # Should have called httpx.get twice (once for initial, once after expiration)
        assert mock_get.call_count == 2
        assert result1 == result2 == result3

    @patch("authutils.token.keys.get_keys_url")
    @patch("authutils.token.keys.httpx.get")
    def test_cache_size_limiting(
        self, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test that cache size is limited to prevent memory overload."""
        # Mock get_keys_url to return JWKS URL based on issuer
        mock_get_keys_url.side_effect = lambda iss: f"{iss}/.well-known/jwks.json"

        # Create a mock that returns JWKS with matching kid
        def mock_get_response(url):
            response = Mock()
            # Extract kid from the URL or create one that matches tokens
            # For this test, we create a JWKS that has keys for all kids
            response.json.return_value = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": f"key-{i}",
                        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",  # pragma: allowlist secret
                        "e": "AQAB",
                    }
                    for i in range(10)
                ]
            }
            return response

        mock_get.side_effect = mock_get_response

        # Save original cache size limit
        original_limit = keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE

        try:
            # Temporarily set a small cache limit for testing
            keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE = 5

            # Generate tokens from different issuers
            tokens = []
            for i in range(10):
                hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
                payload = {
                    "iss": f"https://issuer-{i}.example.com",
                    "sub": "test-user",
                    "kid": f"key-{i}",
                }
                header = {"alg": "HS256", "typ": "JWT", "kid": f"key-{i}"}
                token = jwt.encode(header, payload, hs_key)
                tokens.append(token)

            # Fetch keys for all tokens
            for token in tokens:
                keys_module.get_any_public_key_for_token(token)

            # Cache should not exceed the limit
            assert len(keys_module._token_public_key_cache) <= 5

        finally:
            # Restore original cache size limit
            keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE = original_limit

    def test_cache_eviction_removes_oldest_entry(self):
        """Test that LRU eviction removes the oldest entry when cache is full."""
        # Save original cache size limit
        original_limit = keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE

        try:
            # Set a very small cache limit for testing
            keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE = 2

            # Directly populate cache with manually controlled entries
            keys_module._token_public_key_cache["issuer-0:key-0"] = {
                "key": b"test_key_0",
                "expires_at": 100.0,
            }
            keys_module._token_public_key_cache["issuer-1:key-1"] = {
                "key": b"test_key_1",
                "expires_at": 200.0,
            }

            assert len(keys_module._token_public_key_cache) == 2

            # Trigger eviction by attempting to save a new entry
            # This will call _save_public_key_to_cache which handles eviction
            keys_module._save_public_key_to_cache(
                "issuer-2:key-2", b"test_key_2", cache_ttl=300
            )

            # Cache should have exactly 2 entries
            assert len(keys_module._token_public_key_cache) == 2

            # Entry with earliest expiration (100.0) should have been evicted
            assert "issuer-0:key-0" not in keys_module._token_public_key_cache

            # Entries with later expirations should still be in cache
            assert "issuer-1:key-1" in keys_module._token_public_key_cache
            assert "issuer-2:key-2" in keys_module._token_public_key_cache

        finally:
            # Restore original cache size limit
            keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE = original_limit

    def test_malformed_token_raises_error(self):
        """Test that malformed tokens raise JWTError."""
        with pytest.raises(JWTError):
            keys_module.get_any_public_key_for_token("not.a.valid.token")

    def test_missing_issuer_raises_error(self):
        """Test that tokens missing issuer raise JWTError."""
        hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
        payload = {
            "sub": "test-user",
            "kid": "test-key-id",
            # Missing "iss"
        }
        header = {"alg": "HS256", "typ": "JWT", "kid": "test-key-id"}
        token = jwt.encode(header, payload, hs_key)

        with pytest.raises(JWTError):
            keys_module.get_any_public_key_for_token(token)

    @patch("authutils.token.keys.httpx.get")
    def test_network_error_raises_error(self, mock_get, valid_token):
        """Test that network errors are properly handled."""
        mock_get.side_effect = Exception("Network error")

        with pytest.raises(JWTError) as exc_info:
            keys_module.get_any_public_key_for_token(valid_token)

    @patch("authutils.token.keys.httpx.get")
    def test_no_matching_key_in_jwks_raises_error(self, mock_get, valid_token):
        """Test that missing key in JWKS raises JWTError."""
        mock_jwks_response = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "different-key-id",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",  # pragma: allowlist secret
                    "e": "AQAB",
                }
            ]
        }

        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_get.return_value = mock_response

        with pytest.raises(JWTError) as exc_info:
            keys_module.get_any_public_key_for_token(valid_token)

    @patch("authutils.token.keys.get_keys_url")
    @patch("authutils.token.keys.httpx.get")
    @patch("authutils.token.keys.time.time")
    def test_custom_cache_ttl(
        self, mock_time, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test that custom cache TTL is respected."""
        mock_get_keys_url.return_value = (
            "https://example.com/issuer/.well-known/jwks.json"
        )
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_get.return_value = mock_response

        current_time = 1000.0
        mock_time.side_effect = [
            current_time,  # First cache write
            current_time + 100,  # Check within custom TTL (150 seconds)
        ]

        # First call with custom TTL of 150 seconds
        result1 = keys_module.get_any_public_key_for_token(valid_token, cache_ttl=150)

        # Second call within custom TTL
        result2 = keys_module.get_any_public_key_for_token(valid_token, cache_ttl=150)

        # Should have only called httpx.get once (second call was cached)
        assert mock_get.call_count == 1
        assert result1 == result2

    @patch("authutils.token.keys.httpx.get")
    def test_different_kids_different_cache_entries(self, mock_get, mock_jwks_response):
        """Test that tokens with different kids are cached separately."""
        # Create a mock that returns JWKS with matching kids
        def mock_get_response(url):
            response = Mock()
            response.json.return_value = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": f"key-{i}",
                        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",  # pragma: allowlist secret
                        "e": "AQAB",
                    }
                    for i in range(2)
                ]
            }
            return response

        mock_get.side_effect = mock_get_response

        # Create two tokens with different kids
        tokens = []
        for i in range(2):
            hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
            payload = {
                "iss": "https://same-issuer.example.com",
                "sub": "test-user",
            }
            header = {"alg": "HS256", "typ": "JWT", "kid": f"key-{i}"}
            token = jwt.encode(header, payload, hs_key)
            tokens.append(token)

        # Fetch keys for both tokens
        result1 = keys_module.get_any_public_key_for_token(tokens[0])
        result2 = keys_module.get_any_public_key_for_token(tokens[1])

        # Should have 2 entries in cache (different kids)
        assert len(keys_module._token_public_key_cache) == 2

    @patch("authutils.token.keys.httpx.get")
    def test_different_issuers_different_cache_entries(
        self, mock_get, mock_jwks_response
    ):
        """Test that tokens from different issuers are cached separately."""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_get.return_value = mock_response

        # Create two tokens from different issuers
        tokens = []
        for i in range(2):
            hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
            payload = {
                "iss": f"https://issuer-{i}.example.com",
                "sub": "test-user",
            }
            header = {"alg": "HS256", "typ": "JWT", "kid": "test-key-id"}
            token = jwt.encode(header, payload, hs_key)
            tokens.append(token)

        # Fetch keys for both tokens
        result1 = keys_module.get_any_public_key_for_token(tokens[0])
        result2 = keys_module.get_any_public_key_for_token(tokens[1])

        # Should have 2 entries in cache (different issuers)
        assert len(keys_module._token_public_key_cache) == 2

    @patch("authutils.token.keys.httpx.get")
    def test_cache_key_format(self, mock_get, valid_token, mock_jwks_response):
        """Test that cache keys follow the expected format 'issuer:kid'."""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_get.return_value = mock_response

        keys_module.get_any_public_key_for_token(valid_token)

        # Check cache key format
        cache_keys = list(keys_module._token_public_key_cache.keys())
        assert len(cache_keys) == 1
        assert ":" in cache_keys[0]
        assert cache_keys[0].startswith("https://example.com/issuer:")
