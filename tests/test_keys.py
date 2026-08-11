"""
Unit tests for authutils.token.keys module, specifically
for `get_any_public_key_for_token_async`
"""

import time
from unittest.mock import AsyncMock, Mock, patch

import anyio
import pytest
from joserfc import jwk, jwt

import authutils.token.keys as keys_module
from authutils.errors import JWTError

TEST_ISSUER = "https://example.com/issuer"


async def _get_key(token, **kwargs):
    """
    Look up a key, defaulting the allowlist to the issuer the test tokens carry.

    allowed_issuers is required, but most tests below are about caching, kid
    selection, or JWKS parsing; spelling it out at every call would bury the
    assertion each one actually makes. Tests that care about the allowlist call
    get_any_public_key_for_token_async directly.
    """
    kwargs.setdefault("allowed_issuers", [TEST_ISSUER])
    return await keys_module.get_any_public_key_for_token_async(token, **kwargs)


@pytest.fixture
def mock_rsa_key():
    """An RSA JWK, as published in a JWKS document."""
    return {
        "kty": "RSA",
        "kid": "test-key-id",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",  # pragma: allowlist secret
        "e": "AQAB",
    }


@pytest.mark.anyio
class TestGetAnyPublicKeyForToken:
    """Tests for get_any_public_key_for_token_async."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear the cache before and after each test."""
        keys_module.clear_public_key_cache()
        yield
        keys_module.clear_public_key_cache()

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

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_successful_key_retrieval(
        self, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test successful retrieval of a public key from a valid token."""
        mock_get_keys_url.return_value = (
            "https://example.com/issuer/.well-known/jwks.json"
        )
        mock_get.return_value = mock_jwks_response

        # First call should fetch from network
        result = await _get_key(valid_token)

        assert result is not None
        assert isinstance(result, (str, bytes))
        mock_get.assert_called_once()

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_cache_hit(
        self, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test that cache returns the same key on second call."""
        mock_get_keys_url.return_value = (
            "https://example.com/issuer/.well-known/jwks.json"
        )
        mock_get.return_value = mock_jwks_response

        # First call
        result1 = await _get_key(valid_token)
        # Second call
        result2 = await _get_key(valid_token)

        # Should have fetched once (second call was served from cache)
        assert mock_get.call_count == 1
        assert result1 == result2

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    @patch("authutils.token.keys.time.time")
    async def test_cache_expiration(
        self, mock_time, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test that cache entries expire after TTL."""
        mock_get_keys_url.return_value = (
            "https://example.com/issuer/.well-known/jwks.json"
        )
        mock_get.return_value = mock_jwks_response

        # Mock time progression
        current_time = 1000.0
        mock_time.return_value = current_time

        # First call
        result1 = await _get_key(valid_token, cache_ttl=300)

        # Second call within TTL (should be cached)
        result2 = await _get_key(valid_token, cache_ttl=300)

        # Third call after TTL (should fetch again)
        mock_time.return_value = current_time + 400
        result3 = await _get_key(valid_token, cache_ttl=300)

        # Should have fetched twice (once initially, once after expiration)
        assert mock_get.call_count == 2
        assert result1 == result2 == result3

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_cache_size_limiting(
        self, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test that cache size is limited to prevent memory overload."""
        # Mock get_keys_url to return JWKS URL based on issuer
        mock_get_keys_url.side_effect = lambda iss: f"{iss}/.well-known/jwks.json"

        # A JWKS carrying a key for every kid the tokens below will ask for.
        mock_get.return_value = {
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

        # Save original cache size limit
        original_limit = keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE

        try:
            # Temporarily set a small cache limit for testing
            keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE = 5

            # Generate tokens from different issuers
            issuers = [f"https://issuer-{i}.example.com" for i in range(10)]
            tokens = []
            for i in range(10):
                hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
                payload = {
                    "iss": issuers[i],
                    "sub": "test-user",
                    "kid": f"key-{i}",
                }
                header = {"alg": "HS256", "typ": "JWT", "kid": f"key-{i}"}
                token = jwt.encode(header, payload, hs_key)
                tokens.append(token)

            # Fetch keys for all tokens
            for token in tokens:
                await _get_key(token, allowed_issuers=issuers)

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

    async def test_malformed_token_raises_error(self):
        """Test that malformed tokens raise JWTError."""
        with pytest.raises(JWTError):
            await _get_key("not.a.valid.token")

    async def test_missing_issuer_raises_error(self):
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
            await _get_key(token)

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_network_error_raises_error(
        self, mock_get, mock_get_keys_url, valid_token
    ):
        """A failed JWKS fetch surfaces as JWTError, not the raw transport error."""
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.side_effect = Exception("Network error")

        with pytest.raises(JWTError, match="Could not fetch JWKS"):
            await _get_key(valid_token)

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_no_matching_key_in_jwks_raises_error(
        self, mock_get, mock_get_keys_url, valid_token
    ):
        """A JWKS document publishing no keys at all raises JWTError."""
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = {"keys": []}

        with pytest.raises(JWTError, match="Got no keys"):
            await _get_key(valid_token)

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    @patch("authutils.token.keys.time.time")
    async def test_custom_cache_ttl(
        self, mock_time, mock_get, mock_get_keys_url, valid_token, mock_jwks_response
    ):
        """Test that custom cache TTL is respected."""
        mock_get_keys_url.return_value = (
            "https://example.com/issuer/.well-known/jwks.json"
        )
        mock_get.return_value = mock_jwks_response

        current_time = 1000.0
        mock_time.return_value = current_time

        # First call with custom TTL of 150 seconds
        result1 = await _get_key(valid_token, cache_ttl=150)

        # Second call within custom TTL
        mock_time.return_value = current_time + 100
        result2 = await _get_key(valid_token, cache_ttl=150)

        # Should have fetched once (second call was served from cache)
        assert mock_get.call_count == 1
        assert result1 == result2

    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    async def test_different_kids_different_cache_entries(
        self, mock_get_keys_url, mock_get, mock_jwks_response
    ):
        """Test that tokens with different kids are cached separately."""
        mock_get_keys_url.return_value = _JWKS_URL

        # A JWKS carrying a key for each kid the tokens below ask for.
        mock_get.return_value = {
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
        issuer = ["https://same-issuer.example.com"]
        result1 = await _get_key(tokens[0], allowed_issuers=issuer)
        result2 = await _get_key(tokens[1], allowed_issuers=issuer)

        # Should have 2 entries in cache (different kids)
        assert len(keys_module._token_public_key_cache) == 2

    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    async def test_different_issuers_different_cache_entries(
        self, mock_get_keys_url, mock_get, mock_jwks_response
    ):
        """Test that tokens from different issuers are cached separately."""
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = mock_jwks_response

        # Create two tokens from different issuers
        issuers = [f"https://issuer-{i}.example.com" for i in range(2)]
        tokens = []
        for i in range(2):
            hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
            payload = {
                "iss": issuers[i],
                "sub": "test-user",
            }
            header = {"alg": "HS256", "typ": "JWT", "kid": "test-key-id"}
            token = jwt.encode(header, payload, hs_key)
            tokens.append(token)

        # Fetch keys for both tokens
        result1 = await _get_key(tokens[0], allowed_issuers=issuers)
        result2 = await _get_key(tokens[1], allowed_issuers=issuers)

        # Should have 2 entries in cache (different issuers)
        assert len(keys_module._token_public_key_cache) == 2

    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    async def test_cache_key_format(
        self, mock_get_keys_url, mock_get, valid_token, mock_jwks_response
    ):
        """Test that cache keys follow the expected format 'issuer:kid'."""
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = mock_jwks_response

        await _get_key(valid_token)

        # Check cache key format
        cache_keys = list(keys_module._token_public_key_cache.keys())
        assert len(cache_keys) == 1
        assert ":" in cache_keys[0]
        assert cache_keys[0].startswith("https://example.com/issuer:")

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_kid_not_published_by_issuer_raises(
        self, mock_get, mock_get_keys_url, valid_token, mock_rsa_key
    ):
        """
        A token naming a kid the issuer does not publish is refused.

        Falling back to some other published key would defeat kid pinning, key
        rotation, and revocation-by-removal: a token signed with a retired key
        would keep validating against whatever key happened to be listed first.
        """
        mock_get_keys_url.return_value = _JWKS_URL
        rotated_key = dict(mock_rsa_key, kid="some-other-kid")
        mock_get.return_value = {"keys": [rotated_key]}

        with pytest.raises(JWTError) as exc_info:
            await _get_key(valid_token)

        assert "test-key-id" in str(exc_info.value)
        assert "some-other-kid" in str(exc_info.value)

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_legacy_kid_pem_pair_format_supported(
        self, mock_get, mock_get_keys_url, valid_token
    ):
        """
        A legacy `/jwt/keys` response of [kid, pem] pairs resolves to its PEM.

        Gen3 deployments predating .well-known discovery serve this shape, so
        both formats have to work against the same issuer set.
        """
        mock_get_keys_url.return_value = "https://example.com/issuer/jwt/keys"
        mock_get.return_value = {"keys": [["test-key-id", _PUBLIC_KEY_PEM]]}

        result = await _get_key(valid_token)

        assert result == _PUBLIC_KEY_PEM

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_token_without_kid_uses_first_published_key(
        self, mock_get, mock_get_keys_url, mock_rsa_key
    ):
        """A token declaring no kid falls back to the issuer's first key."""
        mock_get_keys_url.return_value = _JWKS_URL
        first = dict(mock_rsa_key, kid="first-key")
        second = dict(mock_rsa_key, kid="second-key")
        mock_get.return_value = {"keys": [first, second]}

        result = await _get_key(_make_token(kid=None))

        expected = keys_module.get_pem_key(first)[1]
        assert result == expected

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_unrecognized_jwks_entries_are_skipped(
        self, mock_get, mock_get_keys_url, valid_token, mock_rsa_key
    ):
        """Malformed JWKS entries are ignored rather than aborting discovery."""
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = {
            "keys": ["a-bare-string", {"no_kid": True}, None, mock_rsa_key]
        }

        result = await _get_key(valid_token)

        assert result == keys_module.get_pem_key(mock_rsa_key)[1]

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_concurrent_lookups_do_not_corrupt_cache(
        self, mock_get, mock_get_keys_url, mock_rsa_key
    ):
        """
        Concurrent lookups that overflow the cache leave it at its size limit.

        Note this does not on its own demonstrate that the cache lock is
        load-bearing: the current popitem-based eviction happens to survive
        this scenario with the lock removed. It pins the invariant against an
        eviction rewrite that iterates the cache (the "dictionary changed size
        during iteration" failure the lock exists to prevent), which is what
        the lock is actually there for now that only async callers remain.
        """
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = {"keys": [mock_rsa_key]}

        overflow = keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE * 3
        issuers = [f"https://issuer-{i}.example.com" for i in range(overflow)]
        tokens = [_make_token(iss=iss) for iss in issuers]
        errors = []

        async def fetch(token):
            try:
                await _get_key(token, allowed_issuers=issuers)
            except Exception as exc:
                errors.append(exc)

        async with anyio.create_task_group() as tg:
            for token in tokens:
                tg.start_soon(fetch, token)

        assert not errors
        assert (
            len(keys_module._token_public_key_cache)
            == keys_module._TOKEN_PUBLIC_KEY_CACHE_MAX_SIZE
        )

    @pytest.mark.parametrize(
        "jwks_payload",
        [
            pytest.param({}, id="empty_object"),
            pytest.param(None, id="null"),
            pytest.param("", id="empty_string"),
            pytest.param("not json", id="bare_string"),
            pytest.param([], id="empty_list"),
        ],
    )
    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_unusable_jwks_payload_raises(
        self, mock_get, mock_get_keys_url, jwks_payload, valid_token
    ):
        """A JWKS response that carries no usable keys raises JWTError."""
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = jwks_payload

        with pytest.raises(JWTError):
            await _get_key(valid_token)

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_keys_url_discovery_failure_normalized_to_jwt_error(
        self, mock_get, mock_get_keys_url, valid_token
    ):
        """A failure inside keys-URL discovery surfaces as JWTError, not raw."""
        mock_get_keys_url.side_effect = RuntimeError("discovery exploded")

        with pytest.raises(JWTError, match="Could not resolve keys URL"):
            await _get_key(valid_token)

        mock_get.assert_not_called()

    @pytest.mark.parametrize(
        "modulus",
        [
            pytest.param("", id="empty"),
            pytest.param("AA", id="too_short"),
            pytest.param("_", id="undecodable_length"),
            pytest.param("!!!not-base64!!!", id="outside_base64_alphabet"),
            pytest.param("0vx7ag oebGcQ", id="embedded_space"),
        ],
    )
    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_unserializable_key_material_raises(
        self, mock_get, mock_get_keys_url, modulus, valid_token, mock_rsa_key
    ):
        """A published key whose material will not serialize raises JWTError."""
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = {"keys": [dict(mock_rsa_key, n=modulus)]}

        with pytest.raises(JWTError, match="Could not serialize public key"):
            await _get_key(valid_token)


@pytest.mark.anyio
class TestAllowlistIsMandatory:
    """
    The allowlist is the only thing constraining which host key discovery
    contacts, so it cannot be omitted or empty.
    """

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Reset the module-global key cache around each test."""
        keys_module.clear_public_key_cache()
        yield
        keys_module.clear_public_key_cache()

    async def test_omitting_the_allowlist_is_a_type_error(self):
        """Callers cannot skip the allowlist: it has no default."""
        with pytest.raises(TypeError):
            await keys_module.get_any_public_key_for_token_async(_make_token())

    @pytest.mark.parametrize(
        "empty", [pytest.param([], id="list"), pytest.param(set(), id="set")]
    )
    async def test_empty_allowlist_is_a_value_error(self, empty):
        """An empty allowlist is a config bug, not a token failure."""
        with pytest.raises(ValueError, match="allowed_issuers must be non-empty"):
            await keys_module.get_any_public_key_for_token_async(
                _make_token(), allowed_issuers=empty
            )

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_allowlist_may_be_a_generator(
        self, mock_get, mock_get_keys_url, mock_rsa_key
    ):
        """
        A generator allowlist is materialized before use.

        The membership test would otherwise consume it, leaving an empty
        collection that refuses every issuer.
        """
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = {"keys": [mock_rsa_key]}

        result = await keys_module.get_any_public_key_for_token_async(
            _make_token(), allowed_issuers=(i for i in [TEST_ISSUER])
        )

        assert result == keys_module.get_pem_key(mock_rsa_key)[1]


@pytest.mark.anyio
class TestPrivateAddressIssuers:
    """
    An allowlisted issuer is fetched regardless of where it resolves. Gen3 runs
    behind a reverse proxy, in k8s, and through an egress proxy, where the
    issuer routinely resolves to a ClusterIP, a loopback sidecar, or an
    internal ingress.
    """

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Reset the module-global key cache around each test."""
        keys_module.clear_public_key_cache()
        yield
        keys_module.clear_public_key_cache()

    @pytest.mark.parametrize(
        "issuer",
        [
            pytest.param("https://fence-service/user", id="cluster_dns"),
            pytest.param("http://10.96.0.11:8000/user", id="cluster_ip"),
            pytest.param("http://127.0.0.1:8000/user", id="loopback_sidecar"),
            pytest.param("http://172.20.0.10/user", id="eks_cluster_ip"),
        ],
    )
    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_allowlisted_private_issuer_is_fetched(
        self, mock_get, mock_get_keys_url, mock_rsa_key, issuer
    ):
        """An allowlisted issuer on a private address resolves normally."""
        mock_get_keys_url.return_value = f"{issuer}/jwt/keys"
        mock_get.return_value = {"keys": [mock_rsa_key]}

        result = await keys_module.get_any_public_key_for_token_async(
            _make_token(iss=issuer), allowed_issuers=[issuer]
        )

        assert result == keys_module.get_pem_key(mock_rsa_key)[1]


@pytest.mark.anyio
class TestTransportRefusesNonHttpUrls:
    """
    Non-http(s) URLs are refused by httpx, which is why authutils does not
    check schemes itself.

    A compromised allowlisted issuer is the only way such a URL reaches the
    fetch, since jwks_uri comes from the discovery response body. httpx raises
    UnsupportedProtocol before performing any I/O, so no request is made.
    """

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Reset the module-global key cache around each test."""
        keys_module.clear_public_key_cache()
        yield
        keys_module.clear_public_key_cache()

    @pytest.mark.parametrize(
        "bad_url",
        [
            pytest.param("file:///etc/passwd", id="file"),
            pytest.param("gopher://169.254.169.254/x", id="gopher"),
            pytest.param("169.254.169.254/latest", id="no_scheme"),
            pytest.param("", id="empty"),
        ],
    )
    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    async def test_discovered_non_http_url_is_refused(self, mock_get_keys_url, bad_url):
        """A discovered jwks_uri that is not http(s) fails as a JWTError."""
        mock_get_keys_url.return_value = bad_url

        with pytest.raises(JWTError, match="Could not fetch JWKS"):
            await _get_key(_make_token())


@pytest.mark.anyio
class TestIssuerAllowlist:
    """
    The `iss` claim is unverified at key-discovery time, and discovery turns it
    into outbound HTTP. The allowlist is what stops an unauthenticated caller
    from choosing where the server connects.
    """

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Reset the module-global key cache around each test."""
        keys_module.clear_public_key_cache()
        yield
        keys_module.clear_public_key_cache()

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_issuer_outside_allowlist_refused_before_any_request(
        self, mock_get, mock_get_keys_url
    ):
        """An issuer outside the allowlist is refused with no network access."""
        token = _make_token(iss="https://evil.example.net")

        with pytest.raises(JWTError, match="not in the allowed issuers list"):
            await _get_key(token, allowed_issuers=["https://good.example.com"])

        mock_get_keys_url.assert_not_called()
        mock_get.assert_not_called()

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_issuer_inside_allowlist_proceeds(
        self, mock_get, mock_get_keys_url, mock_rsa_key
    ):
        """An allowlisted issuer resolves normally."""
        mock_get_keys_url.return_value = _JWKS_URL
        mock_get.return_value = {"keys": [mock_rsa_key]}
        token = _make_token(iss="https://good.example.com")

        result = await _get_key(token, allowed_issuers=["https://good.example.com"])

        assert result == keys_module.get_pem_key(mock_rsa_key)[1]

    @patch("authutils.token.keys.get_keys_url_async", new_callable=AsyncMock)
    @patch("authutils.token.keys._fetch_jwks_async", new_callable=AsyncMock)
    async def test_allowlist_matching_is_exact_not_prefix(
        self, mock_get, mock_get_keys_url
    ):
        """An issuer that merely prefixes an allowlisted one is still refused."""
        token = _make_token(iss="https://good.example.com.evil.net")

        with pytest.raises(JWTError, match="not in the allowed issuers list"):
            await _get_key(token, allowed_issuers=["https://good.example.com"])

        mock_get_keys_url.assert_not_called()
        mock_get.assert_not_called()


@pytest.mark.anyio
@pytest.mark.anyio
class TestAsyncKeyDiscovery:
    """
    get_any_public_key_for_token_async must enforce every rule the synchronous
    version does, share its cache, and leave the event loop free while it waits
    on the network.
    """

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Reset the module-global key cache around each test."""
        keys_module.clear_public_key_cache()
        yield
        keys_module.clear_public_key_cache()

    async def test_second_lookup_is_served_from_cache(self, mock_rsa_key, monkeypatch):
        """A repeat lookup reuses the cached key instead of refetching."""
        fetched = _stub_async_jwks(monkeypatch, {"keys": [mock_rsa_key]})
        token = _make_token()

        first = await _get_key(token)
        second = await _get_key(token)

        assert first == second
        assert len(fetched) == 1, "second lookup should not have refetched"

    async def test_issuer_outside_allowlist_refused_before_any_request(
        self, mock_rsa_key, monkeypatch
    ):
        """The issuer allowlist is enforced on the async path too, with no I/O."""
        calls = _stub_async_jwks(monkeypatch, {"keys": [mock_rsa_key]})

        with pytest.raises(JWTError, match="not in the allowed issuers list"):
            await _get_key(
                _make_token(iss="https://evil.example.net"),
                allowed_issuers=["https://good.example.com"],
            )

        assert calls == []

    async def test_kid_not_published_by_issuer_raises(self, mock_rsa_key, monkeypatch):
        """Key pinning is enforced on the async path too."""
        _stub_async_jwks(
            monkeypatch, {"keys": [dict(mock_rsa_key, kid="some-other-kid")]}
        )

        with pytest.raises(JWTError, match="test-key-id"):
            await _get_key(_make_token())

    async def test_does_not_block_the_event_loop(self, mock_rsa_key, monkeypatch):
        """
        Other coroutines keep running while key discovery waits on the network.

        This is the whole point of the async variant: with the synchronous
        implementation the loop is held for the duration of a DNS lookup plus
        up to two HTTP round trips, stalling every other in-flight request.
        """
        _stub_async_jwks(monkeypatch, {"keys": [mock_rsa_key]}, latency=0.05)

        ticks = 0
        stop = False

        async def ticker():
            nonlocal ticks
            while not stop:
                ticks += 1
                await anyio.sleep(0.001)

        async with anyio.create_task_group() as tg:
            tg.start_soon(ticker)
            await _get_key(_make_token())
            stop = True

        assert ticks > 5, f"event loop appears to have been blocked (ticks={ticks})"


_JWKS_URL = "https://example.com/issuer/.well-known/jwks.json"

_PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg0HpFHzrLNgQPRs2hJQZSvpMDGpx\n"  # pragma: allowlist secret
    "MSD3xVAZ0nJ7Xn6E6mHnW0PLGN0kZKN1Z1hkGfQzZ5D5tYWbLQmC8cN0Bg==\n"  # pragma: allowlist secret
    "-----END PUBLIC KEY-----\n"
)


def _make_token(
    iss: str = "https://example.com/issuer", kid: str | None = "test-key-id"
) -> str:
    """Build an unverified JWT carrying a given iss and kid, for discovery tests."""
    hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
    header = {"alg": "HS256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    return jwt.encode(header, {"iss": iss, "sub": "test-user"}, hs_key)


def _jwks_response(payload: dict) -> Mock:
    """Build a mock httpx2 response returning a given JWKS document."""
    response = Mock()
    response.json.return_value = payload
    return response


def _stub_async_jwks(
    monkeypatch,
    payload: dict,
    keys_url: str = _JWKS_URL,
    latency: float = 0.0,
) -> list:
    """
    Stub the async discovery and JWKS fetch, recording the URLs requested.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        payload (dict): JWKS document the fetch should return.
        keys_url (str): URL that discovery should resolve to.
        latency (float): Seconds each awaited step should take, for tests that
            need the coroutine to actually yield to the loop.

    Returns:
        list: URLs passed to the JWKS fetch, appended as calls happen.
    """
    fetched = []

    async def fake_get_keys_url_async(iss, force_issuer=None):
        if latency:
            await anyio.sleep(latency)
        return keys_url

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        async def get(self, url, *args, **kwargs):
            fetched.append(url)
            if latency:
                await anyio.sleep(latency)
            return _jwks_response(payload)

    monkeypatch.setattr(
        "authutils.token.keys.get_keys_url_async", fake_get_keys_url_async
    )
    monkeypatch.setattr("authutils.token.keys.httpx2.AsyncClient", FakeAsyncClient)

    return fetched
