"""
Test DPoP functionality in authutils.dpop module.

Organized by the class of thing being validated, mirroring RFC 9449's own
structure (https://datatracker.ietf.org/doc/html/rfc9449).

- Proof construction (generate_dpop_proof, compute_ath)
- Proof header validation (typ, jwk, asymmetric alg) [RFC 9449 4.3]
- Proof signature verification (the proof is signed by the embedded jwk)
- Request binding validation (htm, htu, ath match the actual request)
- Proof freshness / replay (iat window, jti) [RFC 9449 11.1]
- Key binding defense (proof key thumbprint == token cnf.jkt)
- validate_dpop_proof contract (return shape, input guards)
- Stateless nonce lifecycle (generate/verify in isolation)
- DPoP proof nonce requirement (require_nonce inside validate_dpop_proof)
- validate_dpop_request integration (the combined convenience wrapper)
"""

import base64
import hashlib
import json
import os
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import anyio
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwk, jws, jwt
from joserfc.errors import JoseError

import authutils.dpop
from authutils.token import dpop_nonce
from authutils.dpop import (
    DPOP_PROOF_CLOCK_SKEW_LEEWAY,
    DPOP_PROOF_MAX_TTL,
    MAX_DPOP_HEADER_LENGTH,
    MAX_JTI_LENGTH,
    MIN_RSA_KEY_BITS,
    SUPPORTED_DPOP_ALGS,
    compute_ath,
    generate_dpop_proof,
    validate_dpop_proof,
    validate_dpop_request_async,
)
from authutils.errors import (
    InvalidNonceError,
    InvalidNonceErrorResourceServer,
    InvalidNonceErrorAuthorizationServer,
    JWTScopeError,
    JWTPurposeError,
)


def _b64url(raw: bytes) -> str:
    """Base64url-encode without padding, as a JWT segment."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_INVALID_JSON = _b64url(b"{invalid json}")
_EMPTY_JSON = _b64url(b"{}")
_JWT_HEADER = _b64url(b'{"typ":"JWT"}')

_INVALID_JSON_HEADER_NONCE = f"{_INVALID_JSON}.{_EMPTY_JSON}.sig"
_INVALID_JSON_PAYLOAD_NONCE = f"{_JWT_HEADER}.{_INVALID_JSON}.sig"


@pytest.fixture(autouse=True)
def set_shared_secret():
    """Set the cluster secret environment variable before each test."""
    os.environ["DPOP_SHARED_SECRET"] = (
        "test-secret-32chars-minimum-test"  # pragma: allowlist secret
    )
    yield
    os.environ.pop("DPOP_SHARED_SECRET", None)


class TestGenerateDpopProof:
    """Direct unit tests for generate_dpop_proof behavior and edge cases."""

    def test_proof_structure_and_claims(self):
        """Proof carries the RFC 9449 4.2 header params and payload claims."""
        key = jwk.generate_key("EC", "P-256")
        method = "POST"
        url = "https://gen3.example.com/ga4gh/tes/v1/tasks"
        access_token = "test-access-token-123"

        proof = generate_dpop_proof(
            key=key,
            method=method,
            url=url,
            access_token=access_token,
        )

        header = _decode_jwt_header(proof)
        payload = _decode_jwt_payload(proof)

        # JWT Header Assertions (RFC 9449 4.2)
        assert header.get("typ") == "dpop+jwt"
        assert header.get("alg") == "ES256"
        assert "jwk" in header
        assert header["jwk"]["kty"] == "EC"
        # Public key parameters only
        assert "d" not in header["jwk"]

        # JWT Payload Assertions
        assert payload.get("htm") == method
        assert payload.get("htu") == url
        assert "jti" in payload
        assert isinstance(payload["jti"], str)
        assert "iat" in payload
        assert abs(payload["iat"] - int(time.time())) <= 5
        assert payload.get("ath") == compute_ath(access_token)

    def test_htu_strips_query_string(self):
        """htu omits the query string, per RFC 9449 4.2."""
        key = jwk.generate_key("EC", "P-256")
        url_with_query = (
            "https://gen3.example.com/api/v1/resource?param1=foo&param2=bar"
        )
        proof = generate_dpop_proof(
            key=key,
            method="GET",
            url=url_with_query,
        )

        payload = _decode_jwt_payload(proof)
        assert payload["htu"] == "https://gen3.example.com/api/v1/resource"

    def test_nonce_handling(self):
        """A supplied nonce is included; None omits the claim entirely."""
        key = jwk.generate_key("EC", "P-256")
        url = "https://gen3.example.com/api/v1/resource"

        # Nonce provided
        proof_with_nonce = generate_dpop_proof(
            key=key,
            method="GET",
            url=url,
            nonce="server-nonce-xyz-789",
        )
        assert (
            _decode_jwt_payload(proof_with_nonce).get("nonce") == "server-nonce-xyz-789"
        )

        # Nonce is None
        proof_without_nonce = generate_dpop_proof(
            key=key,
            method="GET",
            url=url,
            nonce=None,
        )
        assert "nonce" not in _decode_jwt_payload(proof_without_nonce)

    def test_edge_cases(self):
        """Empty/unicode URLs and long or numeric nonces round-trip intact."""
        key = jwk.generate_key("EC", "P-256")

        # Empty URL
        proof_empty_url = generate_dpop_proof(
            key=key,
            method="GET",
            url="",
        )
        assert _decode_jwt_payload(proof_empty_url).get("htu") == ""

        # Unicode characters in URL
        unicode_url = "https://gen3.example.com/path/ñ/日本語"
        proof_unicode_url = generate_dpop_proof(
            key=key,
            method="GET",
            url=unicode_url,
        )
        assert _decode_jwt_payload(proof_unicode_url).get("htu") == unicode_url

        # Extremely long nonce
        long_nonce = "n" * 2048
        proof_long_nonce = generate_dpop_proof(
            key=key,
            method="GET",
            url="https://gen3.example.com",
            nonce=long_nonce,
        )
        assert _decode_jwt_payload(proof_long_nonce).get("nonce") == long_nonce

        # Numeric string nonce
        numeric_nonce = "9876543210"
        proof_numeric_nonce = generate_dpop_proof(
            key=key,
            method="GET",
            url="https://gen3.example.com",
            nonce=numeric_nonce,
        )
        assert _decode_jwt_payload(proof_numeric_nonce).get("nonce") == numeric_nonce

    @pytest.mark.parametrize(
        "curve, expected_alg",
        [("P-256", "ES256"), ("P-384", "ES384"), ("P-521", "ES512")],
    )
    def test_ec_curve_determines_alg(self, curve, expected_alg):
        """EC algs are curve-bound, so P-384/P-521 keys must not use ES256."""
        key = jwk.ECKey.generate_key(crv=curve)
        proof = generate_dpop_proof(
            key=key, method="GET", url="https://gen3.example.com"
        )
        assert _decode_jwt_header(proof).get("alg") == expected_alg

    def test_bearer_prefixed_access_token_rejected(self):
        """A scheme-prefixed access token is rejected rather than mis-hashed."""
        key = jwk.generate_key("EC", "P-256")
        with pytest.raises(ValueError, match="[Bb]earer"):
            generate_dpop_proof(
                key=key,
                method="GET",
                url="https://gen3.example.com",
                access_token="Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig",  # pragma: allowlist secret
            )

    def test_explicit_alg_matches_key_default(self):
        """
        An explicit `alg` matching the key's auto-selected one is a no-op.

        The override path and the auto-resolution path have to agree, or a
        caller pinning the algorithm it already expects would change behavior.
        """
        key = jwk.generate_key("EC", "P-256")
        proof = generate_dpop_proof(
            key=key, method="GET", url="https://gen3.example.com", alg="ES256"
        )
        assert _decode_jwt_header(proof).get("alg") == "ES256"

    def test_explicit_unsupported_alg_rejected(self):
        """
        A caller-supplied alg outside SUPPORTED_DPOP_ALGS is rejected, so
        "none" and symmetric algs can never produce a usable proof.
        """
        key = jwk.generate_key("EC", "P-256")
        for bad_alg in ("none", "HS256", "HS512"):
            with pytest.raises(ValueError):
                generate_dpop_proof(
                    key=key, method="GET", url="https://gen3.example.com", alg=bad_alg
                )

    def test_disallowed_ec_curve_cannot_produce_a_proof(self):
        """A key on a curve outside the allowlist is refused at generation."""
        key = jwk.ECKey.generate_key(crv="secp256k1")
        with pytest.raises(ValueError, match="Unsupported EC curve"):
            generate_dpop_proof(key=key, method="GET", url="https://gen3.example.com")

    def test_symmetric_key_cannot_produce_a_proof(self):
        """A symmetric key is refused at generation, not silently downgraded."""
        with pytest.raises(ValueError, match="Unsupported key type"):
            generate_dpop_proof(
                key=jwk.OctKey.generate_key(),
                method="GET",
                url="https://gen3.example.com",
            )


class TestComputeAth:
    """Direct unit tests for RFC 9449 access token hash computation."""

    def test_rfc_compliance(self):
        """ath is unpadded base64url of SHA-256, 43 chars, per RFC 9449 4.2."""
        token = "K945938459384593845"
        ath = compute_ath(token)

        assert len(ath) == 43
        assert "=" not in ath

        expected_ath = (
            base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        assert ath == expected_ath

    def test_edge_cases(self):
        """Empty and very long tokens hash fine; non-ASCII raises per the RFC."""
        # Empty token
        empty_ath = compute_ath("")
        assert len(empty_ath) == 43

        # Non-ASCII Unicode token raises UnicodeEncodeError per RFC 9449 4.2
        unicode_token = "token-ñ-日本語-🔑"
        with pytest.raises(UnicodeEncodeError):
            compute_ath(unicode_token)

        # Long token input
        long_token = "a" * 1_000_000
        long_ath = compute_ath(long_token)
        assert len(long_ath) == 43

    def test_bytes_input(self):
        """
        compute_ath is typed to accept `str | bytes`. Confirm bytes
        input produces the same digest as the equivalent str input.
        """
        token_str = "K945938459384593845"
        token_bytes = token_str.encode("ascii")
        assert compute_ath(token_bytes) == compute_ath(token_str)

    @pytest.mark.parametrize(
        "not_a_token",
        [
            pytest.param(None, id="none"),
            pytest.param(12345, id="int"),
            pytest.param(["a"], id="list"),
            pytest.param({"a": 1}, id="dict"),
        ],
    )
    def test_non_str_or_bytes_input_raises_type_error(self, not_a_token):
        """compute_ath rejects anything that is neither str nor bytes."""
        with pytest.raises(TypeError, match="must be str or bytes"):
            compute_ath(not_a_token)


class TestProofHeaderValidation:
    """
    Algorithm Whitelisting & Key Cross-Compatibility, plus header
    well-formedness checks called out in validate_dpop_proof's docstring
    ("Header validation (typ, jwk presence, asymmetric key)").
    """

    def test_rsa_verification(self):
        """An RSA proof key resolves to RS256 without the caller naming an alg."""
        rsa_key = jwk.RSAKey.generate_key()

        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/resource"
        )

        header_b64, _, _ = proof.split(".")
        header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        header_json = json.loads(
            base64.urlsafe_b64decode(header_padded).decode("utf-8")
        )
        assert header_json["alg"] == "RS256"
        assert header_json.get("typ") == "dpop+jwt"
        assert "jwk" in header_json

    def test_algorithm_confusion_injection(self):
        """A valid EC proof whose header alg is swapped to HS256 is rejected."""
        ec_key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            ec_key, "GET", "https://example.com/resource"
        )

        header_b64, payload_b64, signature = proof.split(".")

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

        new_proof = f"{new_header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                new_proof, "GET", "https://example.com/resource"
            )

    @pytest.mark.parametrize(
        "registry_kwargs",
        [
            pytest.param({}, id="algorithms_omitted"),
            pytest.param({"algorithms": None}, id="algorithms_none"),
            pytest.param({"algorithms": set()}, id="algorithms_empty_set"),
            pytest.param({"algorithms": []}, id="algorithms_empty_list"),
        ],
    )
    def test_unpinned_registry_cannot_be_constructed(self, registry_kwargs):
        """
        An unpinned or empty allowlist is refused at registry construction.

        joserfc's get_alg guards with `if self.allowed:`, so a falsy
        collection silently means "allow all recommended algorithms" --
        which includes HS256 and would defeat DPoP algorithm pinning.
        """
        with pytest.raises(ValueError, match="allowlist"):
            authutils.dpop._LargeHeaderRegistry(**registry_kwargs)

    def test_supported_algs_is_immutable(self):
        """SUPPORTED_DPOP_ALGS is a frozenset, so it cannot be emptied at runtime."""
        assert isinstance(SUPPORTED_DPOP_ALGS, frozenset)
        with pytest.raises(AttributeError):
            SUPPORTED_DPOP_ALGS.clear()

    def test_hs256_proof_rejected_end_to_end(self):
        """A symmetric HS256 proof is rejected by validate_dpop_proof."""
        hs_key = jwk.OctKey.generate_key()
        proof = jwt.encode(
            {"typ": "dpop+jwt", "alg": "HS256", "jwk": hs_key.as_dict()},
            {
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()),
                "jti": "hs256-e2e-jti",
            },
            hs_key,
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_algorithm_allowlist_is_pinned_in_the_jws_registry(self):
        """
        The registry itself pins the allowlist, since joserfc ignores
        `algorithms=` on jwt.decode whenever a registry is supplied.

        This is the regression guard for the signature-verification layer:
        without registry-level pinning, jwt.decode accepts every algorithm
        joserfc deems "recommended", including HS256.
        """
        hs_key = jwk.OctKey.generate_key()
        proof = jwt.encode(
            {"typ": "dpop+jwt", "alg": "HS256", "jwk": hs_key.as_dict()},
            {"htm": "GET", "htu": "https://example.com/resource"},
            hs_key,
        )

        with pytest.raises(JoseError):
            jwt.decode(proof, hs_key, registry=authutils.dpop._new_registry())

    def test_private_key_in_header_rejected(self):
        """A jwk header leaking private parameters is rejected."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )
        tampered = _replace_header_field(proof, "jwk", key.as_dict(private=True))

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                tampered, "GET", "https://example.com/resource"
            )

    def test_undersized_rsa_key_rejected(self):
        """An RSA proof key below MIN_RSA_KEY_BITS is rejected."""
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pem = small.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        weak_key = jwk.RSAKey.import_key(pem)
        proof = jwt.encode(
            {
                "typ": "dpop+jwt",
                "alg": "RS256",
                "jwk": weak_key.as_dict(private=False),
            },
            {
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()),
                "jti": "weak-rsa-jti",
            },
            weak_key,
            registry=_large_registry(),
        )

        with pytest.raises(ValueError, match="too small"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_rsa_key_at_minimum_size_accepted(self):
        """An RSA proof key at exactly MIN_RSA_KEY_BITS is accepted."""
        key = jwk.RSAKey.generate_key(MIN_RSA_KEY_BITS)
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        _, client_jwk = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )
        assert client_jwk.as_dict(private=False)["kty"] == "RSA"

    def test_jwk_header_not_an_object_rejected(self):
        """A non-object jwk header value is rejected without a crash."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )
        tampered = _replace_header_field(proof, "jwk", "not-an-object")

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                tampered, "GET", "https://example.com/resource"
            )

    def test_okp_key_rejected(self):
        """OKP/EdDSA keys are not in SUPPORTED_DPOP_ALGS, so they are refused."""
        key = jwk.OKPKey.generate_key("Ed25519")

        with pytest.raises(ValueError, match="[Uu]nsupported key type"):
            authutils.dpop.generate_dpop_proof(
                key, "GET", "https://example.com/resource"
            )

    def test_missing_typ_header_rejected(self):
        """
        RFC 9449 4.3 requires "The typ JOSE Header Parameter has the
        value dpop+jwt." A proof with no `typ` at all must be rejected.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )
        new_proof = _replace_header_field(proof, "typ", remove=True)

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                new_proof, "GET", "https://example.com/resource"
            )

    def test_wrong_typ_header_value_rejected(self):
        """
        A `typ` value other than "dpop+jwt" (e.g. plain "JWT") must be
        rejected, not silently accepted.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )
        new_proof = _replace_header_field(proof, "typ", "JWT")

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                new_proof, "GET", "https://example.com/resource"
            )

    def test_missing_jwk_header_rejected(self):
        """
        validate_dpop_proof's docstring calls out "jwk presence" as a
        validated header condition. A proof missing the `jwk` header
        parameter entirely must be rejected.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )
        new_proof = _replace_header_field(proof, "jwk", remove=True)

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                new_proof, "GET", "https://example.com/resource"
            )

    def test_symmetric_key_signing_rejected(self):
        """
        DPoP proofs must be signed with an asymmetric key so the
        public key can be safely embedded in the `jwk` header. A proof
        actually signed end-to-end with a symmetric (oct) key/HS256 must be
        rejected, independent of whether the signature itself verifies.
        """
        hs_key = jwk.OctKey.generate_key()
        header = {
            "typ": "dpop+jwt",
            "alg": "HS256",
            "jwk": hs_key.as_dict(),
        }
        claims = {
            "htm": "GET",
            "htu": "https://example.com/resource",
            "iat": int(time.time()),
            "jti": "symmetric-key-test-jti",
        }
        proof = jwt.encode(header, claims, hs_key)

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_symmetric_jwk_declaring_an_allowlisted_alg_rejected(self):
        """An oct jwk is rejected even when the header claims an asymmetric alg."""
        oct_key = jwk.OctKey.generate_key()
        proof = _build_unverifiable_proof(
            header={"typ": "dpop+jwt", "alg": "ES256", "jwk": oct_key.as_dict()},
            claims=_minimal_proof_claims(),
        )

        with pytest.raises(ValueError, match="asymmetric key"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_unimportable_embedded_jwk_rejected(self):
        """A jwk missing required key parameters is rejected, not raised through."""
        proof = _build_unverifiable_proof(
            header={
                "typ": "dpop+jwt",
                "alg": "ES256",
                "jwk": {"kty": "EC", "crv": "P-256"},
            },
            claims=_minimal_proof_claims(),
        )

        with pytest.raises(ValueError, match="could not be imported"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_disallowed_ec_curve_rejected(self):
        """
        A secp256k1 proof key is rejected by the curve allowlist.

        The header claims ES256 so that the alg allowlist passes and the curve
        check is actually the thing doing the rejecting; ES256K would otherwise
        be caught earlier and this would pass for the wrong reason.
        """
        secp_key = jwk.ECKey.generate_key(crv="secp256k1")
        proof = _build_unverifiable_proof(
            header={
                "typ": "dpop+jwt",
                "alg": "ES256",
                "jwk": secp_key.as_dict(private=False),
            },
            claims=_minimal_proof_claims(),
        )

        with pytest.raises(ValueError, match="disallowed EC curve"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    @pytest.mark.parametrize(
        "malformed",
        [
            pytest.param("not.a.jwt", id="non_base64_segments"),
            pytest.param("onlyonesegment", id="single_segment"),
            pytest.param("two.segments", id="two_segments"),
            pytest.param("a.b.c.d", id="four_segments"),
            pytest.param("...", id="empty_segments"),
        ],
    )
    def test_malformed_compact_jws_rejected(self, malformed):
        """A value that is not a well-formed compact JWS is rejected as ValueError."""
        with pytest.raises(ValueError, match="Invalid DPoP proof"):
            authutils.dpop.validate_dpop_proof(
                malformed, "GET", "https://example.com/resource"
            )


class TestProofSignatureVerification:
    """
    The proof must actually be signed by the key embedded in its own jwk
    header. Without this, the jwk header is an unauthenticated attacker-chosen
    value and every downstream check (including cnf.jkt key binding) is
    meaningless.
    """

    def test_proof_signed_by_key_other_than_embedded_jwk_rejected(self):
        """
        A proof signed by one key but advertising another key's jwk is rejected.

        This is the core DPoP forgery: an attacker who has observed a victim's
        public key would otherwise be able to mint proofs whose thumbprint
        matches the victim's cnf.jkt.
        """
        victim_key = jwk.ECKey.generate_key(crv="P-256")
        attacker_key = jwk.ECKey.generate_key(crv="P-256")

        proof = authutils.dpop.generate_dpop_proof(
            attacker_key, "GET", "https://example.com/resource"
        )
        forged = _replace_header_field(proof, "jwk", victim_key.as_dict(private=False))

        with pytest.raises(ValueError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                forged, "GET", "https://example.com/resource"
            )

        assert "bad_signature" in str(exc_info.value)

    def test_validly_signed_non_object_payload_rejected(self):
        """
        A correctly signed proof whose payload is a JSON string is rejected.

        joserfc's jwt.decode does not require an object payload -- it returns
        the bare string as `claims`. Without the shape check, claim lookups
        would degrade into substring tests (`"nonce" in claims`) and
        `claims.get(...)` would raise AttributeError.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = jws.serialize_compact(
            {"alg": "ES256", "typ": "dpop+jwt", "jwk": key.as_dict(private=False)},
            b'"just a string"',
            key,
        )

        with pytest.raises(ValueError, match="payload is not a JSON object"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_tampered_payload_rejected(self):
        """Re-encoding the payload under the original signature is rejected."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )
        tampered = _replace_payload_field(proof, "jti", "attacker-chosen-jti")

        with pytest.raises(ValueError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                tampered, "GET", "https://example.com/resource"
            )

        assert "bad_signature" in str(exc_info.value)

    def test_tampered_signature_rejected(self):
        """A proof whose signature segment has been altered is rejected."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )
        header_b64, payload_b64, signature = proof.split(".")
        flipped = ("B" if signature[0] != "B" else "C") + signature[1:]

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                f"{header_b64}.{payload_b64}.{flipped}",
                "GET",
                "https://example.com/resource",
            )

    def test_signature_failure_surfaces_as_value_error_not_jose_error(self):
        """
        A bad signature normalizes to ValueError.

        JoseError does not subclass ValueError, so a caller doing
        `except ValueError: return 401` would otherwise emit a 500 on the most
        common attack path.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        # Retarget the proof at POST and validate a POST request, so every
        # non-signature check passes and only the signature can reject it.
        tampered = _replace_payload_field(proof, "htm", "POST")

        with pytest.raises(ValueError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                tampered, "POST", "https://example.com/resource"
            )

        assert not isinstance(exc_info.value, JoseError)


class TestRequestBindingValidation:
    """
    Confirms a proof is bound to the specific request/token it was
    generated for, per the four checks in validate_dpop_proof's docstring
    (signature, htm, htu, ath).
    """

    def test_htm_mismatch_rejected(self):
        """
        A proof generated for GET must not validate against a request
        made with a different HTTP method.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "POST", "https://example.com/resource"
            )

    def test_htu_mismatch_rejected(self):
        """
        A proof generated for one URL must not validate against a
        request made to a different URL.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/other-resource"
            )

    def test_default_port_is_normalized_away(self):
        """https://host/x and https://host:443/x compare equal (RFC 9110 4.2)."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com:443/resource"
        )

        claims, _ = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )
        assert claims["htu"] == "https://example.com/resource"

    def test_non_default_port_remains_significant(self):
        """A non-default port is not normalized away, so it must still match."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com:8443/resource"
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_htu_containing_query_string_rejected(self):
        """A proof whose htu retains a query string is rejected, not normalized."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource?admin=1",
                "iat": int(time.time()),
                "jti": "htu-query-jti",
            },
        )

        with pytest.raises(ValueError, match="query"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_missing_ath_when_access_token_presented_rejected(self):
        """RFC 9449 4.2 requires ath whenever a token accompanies the proof."""
        key = jwk.ECKey.generate_key(crv="P-256")
        # Generated without access_token, so no ath claim is present.
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError, match="ath"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", "some-access-token"
            )

    def test_htu_trailing_slash_is_not_normalized(self):
        """
        Documents current strict string-matching behavior for htu.
        RFC 9449 only specifies stripping query/fragment before comparison;
        it does not require normalizing trailing slashes, so a proof for
        ".../resource" should NOT validate against ".../resource/".
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource/"
            )

    def test_htu_path_parameters_are_significant(self):
        """
        A proof for "/resource" does not validate a request to "/resource;x".

        Path parameters are part of the path (RFC 3986 3.3), so dropping them
        during normalization would let one proof satisfy two distinct target
        URIs. urlparse peels them into a separate field and would do exactly
        that; urlsplit keeps them in the path.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError, match="htu mismatch"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource;evil"
            )

    def test_htu_with_path_parameters_round_trips(self):
        """A proof minted for a URL carrying path parameters validates itself."""
        key = jwk.ECKey.generate_key(crv="P-256")
        url = "https://example.com/resource;v=1"
        proof = authutils.dpop.generate_dpop_proof(key, "GET", url)

        claims, _ = authutils.dpop.validate_dpop_proof(proof, "GET", url)

        assert claims["htu"] == url

    @pytest.mark.parametrize(
        "bad_url",
        [pytest.param("", id="empty"), pytest.param(None, id="none")],
    )
    def test_missing_request_url_rejected(self, bad_url):
        """
        An empty request_url is a caller bug, not a match against an empty htu.

        generate_dpop_proof will mint a proof with htu="" for an empty URL, and
        an empty request_url normalizes to "" as well, so comparing them would
        accept that proof for any resource.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(key, "GET", "")

        with pytest.raises(ValueError, match="request_url"):
            authutils.dpop.validate_dpop_proof(proof, "GET", bad_url)

    def test_request_method_case_insensitive_by_design(self):
        """
        Documents that htm comparison is intentionally
        case-INsensitive (_validate_proof_claims compares
        request_method.upper() != htm_value.upper()), so a lowercase
        request method must still match an uppercase htm claim.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        dpop_claims, _ = authutils.dpop.validate_dpop_proof(
            proof, "get", "https://example.com/resource"
        )
        assert dpop_claims["htm"] == "GET"

    def test_ath_mismatch_rejected(self):
        """
        A proof generated with the hash of one access token must not
        validate when checked against a different access token's value,
        even when the key binding would otherwise be fine.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", access_token="token-A"
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", "token-B"
            )

    def test_non_ascii_access_token_rejected_as_value_error(self):
        """
        A non-ASCII access token yields ValueError, not UnicodeEncodeError.

        RFC 9449 4.2 defines ath over the token's ASCII encoding, so a
        non-ASCII token cannot be hashed; that must surface as a 401-shaped
        failure rather than an unhandled 500.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", access_token="ascii-token"
        )

        with pytest.raises(ValueError, match="Could not compute ath"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", "t€ken"
            )


class TestProofFreshnessAndReplay:
    """
    Freshness and replay protections. DPOP_PROOF_MAX_TTL bounds how long
    a proof's `iat` may be considered fresh.
    """

    def test_stale_iat_rejected(self):
        """
        A proof whose `iat` is well outside DPOP_PROOF_MAX_TTL in the
        past must be rejected, per RFC 9449's guidance that servers "only
        accept DPoP proofs for a limited time after their creation."
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        stale_iat = int(time.time()) - DPOP_PROOF_MAX_TTL - 3600
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": stale_iat,
                "jti": "stale-iat-test-jti",
            },
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_future_iat_beyond_skew_rejected(self):
        """
        A proof whose `iat` is far in the future (well beyond
        reasonable clock skew) must be rejected -- otherwise a client could
        pre-generate proofs valid arbitrarily far ahead of time.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        future_iat = int(time.time()) + DPOP_PROOF_MAX_TTL + 3600
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": future_iat,
                "jti": "future-iat-test-jti",
            },
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_duplicate_jti_rejected_with_callback(self):
        """Replaying a proof is rejected when jti_seen_callback reports reuse."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        seen = set()

        def jti_seen_callback(jti):
            if jti in seen:
                return True
            seen.add(jti)
            return False

        # First use is accepted and records the jti.
        authutils.dpop.validate_dpop_proof(
            proof,
            "GET",
            "https://example.com/resource",
            jti_seen_callback=jti_seen_callback,
        )

        # Replaying the exact same proof (same jti) is rejected.
        with pytest.raises(ValueError, match="replay"):
            authutils.dpop.validate_dpop_proof(
                proof,
                "GET",
                "https://example.com/resource",
                jti_seen_callback=jti_seen_callback,
            )

    def test_distinct_jtis_both_accepted_with_callback(self):
        """Two separately generated proofs have distinct jtis and both pass."""
        key = jwk.ECKey.generate_key(crv="P-256")
        seen = set()

        def jti_seen_callback(jti):
            if jti in seen:
                return True
            seen.add(jti)
            return False

        for _ in range(2):
            proof = authutils.dpop.generate_dpop_proof(
                key, "GET", "https://example.com/resource"
            )
            authutils.dpop.validate_dpop_proof(
                proof,
                "GET",
                "https://example.com/resource",
                jti_seen_callback=jti_seen_callback,
            )

        assert len(seen) == 2, "each generated proof should carry a unique jti"

    def test_no_replay_protection_without_callback(self):
        """Without a callback the module is stateless, so a proof reuses freely."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        first, _ = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )
        second, _ = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )

        assert first["jti"] == second["jti"]

    def test_iat_just_within_max_ttl_accepted(self):
        """A proof at the inner edge of DPOP_PROOF_MAX_TTL still validates."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()) - DPOP_PROOF_MAX_TTL + 10,
                "jti": "inner-edge-jti",
            },
        )

        claims, _ = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )
        assert claims["jti"] == "inner-edge-jti"

    def test_iat_within_clock_skew_leeway_accepted(self):
        """A slightly future iat inside the skew leeway is tolerated."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()) + DPOP_PROOF_CLOCK_SKEW_LEEWAY - 10,
                "jti": "skew-leeway-jti",
            },
        )

        claims, _ = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )
        assert claims["jti"] == "skew-leeway-jti"

    def test_expired_exp_rejected(self):
        """An exp already in the past is rejected."""
        key = jwk.ECKey.generate_key(crv="P-256")
        now = int(time.time())
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": now,
                "exp": now - 1,
                "jti": "expired-exp-jti",
            },
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_missing_iat_rejected(self):
        """
        A proof with no iat at all is rejected.

        iat is what bounds the replay window, so a proof omitting it would
        otherwise be accepted indefinitely.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "jti": "missing-iat-jti",
            },
        )

        with pytest.raises(ValueError, match="missing required 'iat' claim"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    @pytest.mark.parametrize(
        "bad_iat",
        [
            pytest.param("9999999999", id="string"),
            pytest.param(None, id="none"),
            pytest.param(True, id="bool"),
            pytest.param([1], id="list"),
            pytest.param({"a": 1}, id="dict"),
        ],
    )
    def test_non_numeric_iat_raises_value_error(self, bad_iat):
        """A non-numeric iat yields ValueError, never an uncaught TypeError."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": bad_iat,
                "jti": "bad-iat-jti",
            },
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    @pytest.mark.parametrize(
        "bad_exp",
        [
            pytest.param("9999999999", id="string"),
            pytest.param(None, id="none"),
            pytest.param([1], id="list"),
        ],
    )
    def test_non_numeric_exp_raises_value_error(self, bad_exp):
        """A non-numeric exp yields ValueError, never an uncaught TypeError."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()),
                "exp": bad_exp,
                "jti": "bad-exp-jti",
            },
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_jose_error_never_escapes_as_non_value_error(self):
        """
        Freshness failures surface as ValueError, not a bare JoseError.

        JoseError does not subclass ValueError, so a caller doing
        `except ValueError: return 401` would otherwise emit a 500.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()) - DPOP_PROOF_MAX_TTL - 3600,
                "jti": "contract-jti",
            },
        )

        with pytest.raises(ValueError) as exc_info:
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

        assert not isinstance(
            exc_info.value, JoseError
        ), "validate_dpop_proof must normalize JoseError to ValueError"


@pytest.mark.anyio
class TestKeyBindingDefense:
    """Bidirectional Binding (Stolen Token Defense)"""

    def test_stolen_token_defense(self):
        """A proof signed by the attacker's key cannot carry Alice's token."""
        alice_key = jwk.ECKey.generate_key(crv="P-256")
        alice_thumbprint = alice_key.thumbprint()

        alice_token_payload = {"sub": "alice", "cnf": {"jkt": alice_thumbprint}}
        hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
        alice_token = jwt.encode(
            {"alg": "HS256", "typ": "JWT"},
            alice_token_payload,
            hs_key,
        )

        attacker_key = jwk.ECKey.generate_key(crv="P-256")

        # The attacker CAN mint a well-formed proof over Alice's token -- the ath
        # claim is only a hash of a token they hold. cnf.jkt is what stops them.
        attacker_proof = authutils.dpop.generate_dpop_proof(
            attacker_key, "GET", "https://example.com/resource", alice_token
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                attacker_proof, "GET", "https://example.com/resource", alice_token
            )

    @pytest.mark.parametrize(
        "cnf_claim, test_id",
        [
            pytest.param(None, "cnf_absent", id="cnf_absent"),
            pytest.param("not-a-dict", "cnf_not_object", id="cnf_not_object"),
            pytest.param({}, "jkt_absent", id="jkt_absent"),
            pytest.param({"jkt": ""}, "jkt_empty", id="jkt_empty"),
            pytest.param({"jkt": None}, "jkt_null", id="jkt_null"),
            pytest.param({"jkt": ["a"]}, "jkt_list", id="jkt_list"),
        ],
    )
    def test_malformed_cnf_jkt_rejected(self, cnf_claim, test_id):
        """A token whose cnf/cnf.jkt is absent or malformed fails key binding."""
        key = jwk.ECKey.generate_key(crv="P-256")
        payload = {"sub": "alice"}
        if cnf_claim is not None:
            payload["cnf"] = cnf_claim

        hs_key = jwk.OctKey.import_key("test-secret-32chars-minimum-test")
        access_token = jwt.encode({"alg": "HS256", "typ": "JWT"}, payload, hs_key)

        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", access_token
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", access_token
            )

    def test_malformed_access_token_rejected_when_reading_cnf(self):
        """A non-JWT access token yields ValueError, not a JSON/decode crash."""
        key = jwk.ECKey.generate_key(crv="P-256")
        garbage_token = "not.a.jwt"
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", garbage_token
        )

        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", garbage_token
            )

    def test_access_token_payload_that_is_not_a_json_object_rejected(self):
        """A well-formed JWS whose payload is a JSON scalar yields ValueError."""
        key = jwk.ECKey.generate_key(crv="P-256")
        header_b64 = _b64url(json.dumps({"alg": "RS256"}).encode())
        scalar_payload_token = f"{header_b64}.{_b64url(b'0')}.AAAA"
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", scalar_payload_token
        )

        with pytest.raises(ValueError, match="not a JSON object"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource", scalar_payload_token
            )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_validate_dpop_request_cnf_jkt_mismatch_rejected(
        self, mock_validate_jwt, mock_get_public_key
    ):
        """
        validate_dpop_request's docstring specifically calls out
        "Key binding validation (proof key thumbprint == token cnf.jkt)"
        as part of what it does. Here the token's cnf.jkt belongs to a
        different key than the one used to sign the DPoP proof, so
        validation must fail.
        """
        dpop_key = jwk.RSAKey.generate_key()
        other_key = jwk.RSAKey.generate_key()

        # Built manually (rather than via _create_signed_access_token, which
        # always overwrites cnf.jkt with the *signing* key's own thumbprint)
        # so the token is signed by dpop_key but bound (cnf.jkt) to a
        # different key entirely -- the real-world mismatch scenario.
        now = int(time.time())
        payload = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "iat": now,
            "exp": now + 3600,
            "pur": "access",
            "scope": ["openid", "user"],
            "cnf": {"jkt": other_key.thumbprint()},
        }
        access_token = jwt.encode({"alg": "RS256", "typ": "JWT"}, payload, dpop_key)

        proof = authutils.dpop.generate_dpop_proof(
            dpop_key, "GET", "https://example.com/api/resource", access_token
        )

        # validate_dpop_proof reads cnf.jkt straight off the raw access
        # token (not from the mocked validate_jwt claims), so the mock
        # return value doesn't need to reflect cnf itself -- it's only
        # reached if key binding passes.
        mock_get_public_key.return_value = dpop_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        with pytest.raises(ValueError):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
            )


class TestValidateDpopProofContract:
    """
    Return-shape and input-guard tests for validate_dpop_proof itself,
    independent of any specific claim being validated.
    """

    def test_returns_dpop_claims_and_client_jwk_tuple(self):
        """
        Returns the proof's claims and its signing key, so no second extract call.

        A caller that only got the claims back would have to re-parse the proof
        with extract_and_validate_jwk to do anything key-bound with it.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        dpop_claims, client_jwk = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )

        assert dpop_claims["htm"] == "GET"
        assert dpop_claims["htu"] == "https://example.com/resource"
        assert "iat" in dpop_claims
        assert client_jwk.thumbprint() == key.thumbprint()

    def test_jti_missing_rejected(self):
        """A proof with no jti is rejected."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()),
            },
        )

        with pytest.raises(ValueError, match="jti"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_jti_non_string_rejected(self):
        """A non-string jti is rejected rather than compared by length."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()),
                "jti": 12345,
            },
        )

        with pytest.raises(ValueError, match="jti"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_oversized_jti_rejected(self):
        """A jti beyond MAX_JTI_LENGTH is rejected to bound replay-cache size."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()),
                "jti": "j" * (MAX_JTI_LENGTH + 1),
            },
        )

        with pytest.raises(ValueError, match="jti"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    @pytest.mark.parametrize("prefix", ["DPoP ", "dpop ", ""])
    def test_dpop_scheme_prefix_is_stripped(self, prefix):
        """A 'DPoP ' scheme prefix is accepted and stripped, in any casing."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        claims, _ = authutils.dpop.validate_dpop_proof(
            prefix + proof, "GET", "https://example.com/resource"
        )
        assert claims["htm"] == "GET"

    def test_wrong_auth_scheme_prefix_rejected(self):
        """A 'Bearer ' prefix on the DPoP header is rejected, not silently stripped."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError, match="scheme"):
            authutils.dpop.validate_dpop_proof(
                "Bearer " + proof, "GET", "https://example.com/resource"
            )

    def test_oversized_dpop_header_rejected_before_crypto(self):
        """An absurdly long header is rejected before any signature work."""
        with pytest.raises(ValueError, match="exceeds"):
            authutils.dpop.validate_dpop_proof(
                "a" * (MAX_DPOP_HEADER_LENGTH + 1),
                "GET",
                "https://example.com/resource",
            )

    @pytest.mark.parametrize(
        "non_string", [pytest.param(12345, id="int"), pytest.param(["a"], id="list")]
    )
    def test_non_string_dpop_header_rejected(self, non_string):
        """A non-string DPoP header raises ValueError, not AttributeError."""
        with pytest.raises(ValueError):
            authutils.dpop.validate_dpop_proof(
                non_string, "GET", "https://example.com/resource"
            )

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

    def test_proof_with_embedded_whitespace_rejected(self):
        """A proof containing internal whitespace is rejected, not silently split."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError, match="unexpected whitespace"):
            authutils.dpop.validate_dpop_proof(
                f"{proof} trailing-junk", "GET", "https://example.com/resource"
            )

    def test_request_url_with_invalid_port_rejected(self):
        """A request URL whose port is not numeric yields ValueError."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError, match="invalid port"):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com:notaport/resource"
            )

    @pytest.mark.parametrize(
        "bad_method",
        [pytest.param("", id="empty"), pytest.param(None, id="none")],
    )
    def test_missing_request_method_rejected(self, bad_method):
        """An empty or missing request_method yields ValueError, not a silent pass."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource"
        )

        with pytest.raises(ValueError, match="request_method"):
            authutils.dpop.validate_dpop_proof(
                proof, bad_method, "https://example.com/resource"
            )


class TestStatelessNonceLifecycle:
    """
    Tests for generate_stateless_nonce and verify_stateless_nonce,
    exercised directly against authutils.token.dpop_nonce (not through a
    DPoP proof).
    """

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
        os.environ["DPOP_SHARED_SECRET"] = (
            "test-secret-32chars-minimum-test"  # pragma: allowlist secret
        )

        # Remove the environment variable
        old_secret = os.environ.pop("DPOP_SHARED_SECRET", None)

        try:
            with pytest.raises(RuntimeError):
                dpop_nonce.generate_stateless_nonce()
        finally:
            os.environ["DPOP_SHARED_SECRET"] = old_secret

    def test_generate_nonce_with_special_characters_in_secret(self):
        """Nonce generation works with special characters in secret."""
        os.environ["DPOP_SHARED_SECRET"] = "test!@#$%^&*()-_+=[]{}|;':\",./<>?"
        nonce = dpop_nonce.generate_stateless_nonce()
        # Should generate a valid nonce
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        token_obj = jwt.decode(nonce, key=hs_key)
        decoded = token_obj.claims
        assert decoded["purpose"] == "dpop_nonce"

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
        os.environ["DPOP_SHARED_SECRET"] = (
            "completely-different-secret-key-123"  # pragma: allowlist secret
        )

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

    def test_verify_nonce_without_exp_rejected(self):
        """
        A correctly signed nonce carrying no exp is rejected.

        generate_stateless_nonce always sets exp, so one without it is
        malformed. Skipping the check when the claim is absent would make such
        a nonce valid forever, which defeats DPOP_NONCE_TTL entirely.
        """
        hs_key = jwk.OctKey.import_key(os.environ["DPOP_SHARED_SECRET"])
        no_exp = jwt.encode(
            header={"alg": "HS256", "typ": "JWT"},
            claims={"iat": int(time.time()), "purpose": "dpop_nonce"},
            key=hs_key,
        )

        assert dpop_nonce.verify_stateless_nonce(no_exp) is False

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

    @pytest.mark.parametrize(
        "malformed",
        [
            pytest.param("abc.def.ghi", id="non-base64-parts"),
            pytest.param("!!!.!!!.!!!", id="outside-base64-alphabet"),
            pytest.param("a.", id="two-parts"),
            pytest.param("..", id="all-parts-empty"),
            pytest.param("a..", id="empty-payload-and-signature"),
            pytest.param("..c", id="empty-header-and-payload"),
            pytest.param(
                _INVALID_JSON_HEADER_NONCE,
                id="invalid-json-header",
            ),
            pytest.param(
                _INVALID_JSON_PAYLOAD_NONCE,
                id="invalid-json-payload",
            ),
        ],
    )
    def test_verify_nonce_rejects_malformed_string(self, malformed):
        """Returns False for a string that is not a well-formed nonce JWT."""
        assert dpop_nonce.verify_stateless_nonce(malformed) is False

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda nonce: nonce.split(".")[0], id="header-only"),
            pytest.param(
                lambda nonce: ".".join(nonce.split(".")[:2]), id="no-signature"
            ),
            pytest.param(lambda nonce: " " + nonce, id="leading-space"),
            pytest.param(lambda nonce: nonce + " ", id="trailing-space"),
            pytest.param(
                lambda nonce: nonce.replace(".", ". "), id="space-after-separator"
            ),
        ],
    )
    def test_verify_nonce_rejects_mutated_valid_nonce(self, mutate):
        """Returns False once a freshly minted nonce is truncated or padded."""
        nonce = dpop_nonce.generate_stateless_nonce()
        assert dpop_nonce.verify_stateless_nonce(mutate(nonce)) is False

    @pytest.mark.parametrize(
        "not_a_string",
        [
            pytest.param(12345, id="positive-int"),
            pytest.param(0, id="zero"),
            pytest.param(-1, id="negative-int"),
            pytest.param(["a", "b", "c"], id="list"),
            pytest.param([], id="empty-list"),
            pytest.param({"a": "b"}, id="dict"),
            pytest.param({}, id="empty-dict"),
        ],
    )
    def test_verify_nonce_rejects_non_string_input(self, not_a_string):
        """Returns False rather than raising when handed a non-string."""
        assert dpop_nonce.verify_stateless_nonce(not_a_string) is False

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

    @pytest.mark.parametrize(
        "error_class",
        [InvalidNonceErrorResourceServer, InvalidNonceErrorAuthorizationServer],
    )
    def test_nonce_error_bodies_are_not_shared_between_instances(self, error_class):
        """Mutating one nonce error's json does not affect the next instance."""
        first = error_class(new_nonce="nonce-one")
        first.json["error"] = "mutated"

        assert error_class(new_nonce="nonce-two").json["error"] == "use_dpop_nonce"

    @pytest.mark.parametrize(
        "error_class, expected_code",
        [
            (InvalidNonceErrorResourceServer, 401),
            (InvalidNonceErrorAuthorizationServer, 400),
        ],
    )
    def test_nonce_error_describes_its_own_role(self, error_class, expected_code):
        """Each nonce error carries the status and description for its own role."""
        err = error_class(new_nonce="a-nonce")

        assert err.code == expected_code
        assert err.error_headers["DPoP-Nonce"] == "a-nonce"


class TestDpopProofNonceRequirement:
    """
    Tests for DPoP nonce validation and InvalidNonceError handling
    inside validate_dpop_proof, per RFC 9449's server-provided-nonce
    mechanism, parametrized across as_resource_server and the nonce
    verification import path.
    """

    @pytest.mark.parametrize(
        "as_resource_server",
        [
            pytest.param(True, id="resource-server"),
            pytest.param(False, id="auth-server"),
        ],
    )
    def test_nonce_errors_share_a_catchable_base(self, as_resource_server):
        """Either mode's nonce error is catchable as InvalidNonceError."""
        key = jwk.generate_key("EC", "P-256")
        url = "https://gen3.example.com/api/v1/resource"
        proof = generate_dpop_proof(key=key, method="GET", url=url, nonce=None)

        with pytest.raises(InvalidNonceError) as exc_info:
            validate_dpop_proof(
                dpop_header=proof,
                request_method="GET",
                request_url=url,
                require_nonce=True,
                as_resource_server=as_resource_server,
            )

        assert exc_info.value.error_headers["DPoP-Nonce"]

    @pytest.mark.parametrize(
        "as_resource_server, expected_error_cls, expected_status_code",
        [
            (True, InvalidNonceErrorResourceServer, 401),
            (False, InvalidNonceErrorAuthorizationServer, 400),
        ],
    )
    def test_missing_required_nonce(
        self, as_resource_server, expected_error_cls, expected_status_code
    ):
        """A missing nonce under require_nonce raises the mode-specific error."""
        key = jwk.generate_key("EC", "P-256")
        url = "https://gen3.example.com/api/v1/resource"
        proof = generate_dpop_proof(key=key, method="GET", url=url, nonce=None)

        with pytest.raises(expected_error_cls) as exc_info:
            validate_dpop_proof(
                dpop_header=proof,
                request_method="GET",
                request_url=url,
                require_nonce=True,
                as_resource_server=as_resource_server,
            )

        assert exc_info.value.code == expected_status_code
        if as_resource_server:
            _assert_nonce_error_for_resource_server(exc_info.value)
        else:
            _assert_nonce_error_for_authorization_server(exc_info.value)

    @pytest.mark.parametrize(
        "as_resource_server, expected_error_cls, expected_status_code",
        [
            (True, InvalidNonceErrorResourceServer, 401),
            (False, InvalidNonceErrorAuthorizationServer, 400),
        ],
    )
    def test_invalid_nonce_rejected(
        self, as_resource_server, expected_error_cls, expected_status_code
    ):
        """
        Garbage nonce string, no mocking -- exercises the real
        verify_stateless_nonce failure path.
        """
        key = jwk.generate_key("EC", "P-256")
        url = "https://gen3.example.com/api/v1/resource"
        proof = generate_dpop_proof(key=key, method="GET", url=url, nonce="bad-nonce")

        with pytest.raises(expected_error_cls) as exc_info:
            validate_dpop_proof(
                dpop_header=proof,
                request_method="GET",
                request_url=url,
                require_nonce=True,
                secret="test-secret-32chars-minimum-test",  # pragma: allowlist secret
                as_resource_server=as_resource_server,
            )

        assert exc_info.value.code == expected_status_code

    @pytest.mark.parametrize(
        "patch_target",
        [
            "authutils.dpop.verify_stateless_nonce",
            "authutils.token.dpop_nonce.verify_stateless_nonce",
        ],
    )
    def test_invalid_nonce_rejected_regardless_of_import_path(self, patch_target):
        """
        Even with require_nonce=False, a nonce that IS present but fails
        verification must still raise. Parametrized over both the
        dpop-module-local import and the source module, since dpop.py may
        reference verify_stateless_nonce via either path.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        invalid_nonce = "garbage-nonce-not-valid"
        proof = authutils.dpop.generate_dpop_proof(
            key, "GET", "https://example.com/resource", nonce=invalid_nonce
        )

        with patch(patch_target, return_value=False):
            with pytest.raises(
                (InvalidNonceErrorAuthorizationServer, InvalidNonceErrorResourceServer)
            ) as exc_info:
                authutils.dpop.validate_dpop_proof(
                    proof, "GET", "https://example.com/resource", require_nonce=False
                )

        _assert_nonce_error_for_resource_server(exc_info.value)

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

    def test_empty_nonce_claim_accepted_when_nonce_not_required(self):
        """
        A present-but-empty nonce is treated as no nonce when none is required.

        The claim's presence is what routes into nonce validation at all, so an
        empty value has to be distinguished there from a real one; a garbage
        non-empty nonce is still verified and rejected.
        """
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()),
                "jti": "empty-nonce-jti",
                "nonce": "",
            },
        )

        dpop_claims, _ = authutils.dpop.validate_dpop_proof(
            proof, "GET", "https://example.com/resource"
        )

        assert dpop_claims["nonce"] == ""

    def test_garbage_nonce_rejected_even_when_not_required(self):
        """A non-empty but unverifiable nonce is rejected regardless of require_nonce."""
        key = jwk.ECKey.generate_key(crv="P-256")
        proof = _build_raw_dpop_proof(
            key,
            claims={
                "htm": "GET",
                "htu": "https://example.com/resource",
                "iat": int(time.time()),
                "jti": "garbage-nonce-jti",
                "nonce": "not-a-real-nonce",
            },
        )

        with pytest.raises(InvalidNonceErrorResourceServer):
            authutils.dpop.validate_dpop_proof(
                proof, "GET", "https://example.com/resource"
            )

    def test_custom_secret_matching_and_mismatched(self):
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

        # Verification with mismatched secret should fail and raise (InvalidNonceErrorAuthorizationServer, InvalidNonceErrorResourceServer)
        with pytest.raises(
            (InvalidNonceErrorAuthorizationServer, InvalidNonceErrorResourceServer)
        ):
            authutils.dpop.validate_dpop_proof(
                proof,
                "GET",
                "https://example.com/resource",
                require_nonce=True,
                secret="wrong-secret-key-32-chars-long!!",  # pragma: allowlist secret
            )

    def test_custom_secret_mismatch_resource_server(self):
        """A nonce not signed with the supplied secret is rejected as a RS."""
        key = jwk.generate_key("EC", "P-256")
        url = "https://gen3.example.com/api/v1/resource"
        proof = generate_dpop_proof(key=key, method="GET", url=url, nonce="some-nonce")

        with pytest.raises(InvalidNonceErrorResourceServer):
            validate_dpop_proof(
                dpop_header=proof,
                request_method="GET",
                request_url=url,
                require_nonce=True,
                secret="custom-secret-key",  # pragma: allowlist secret
                as_resource_server=True,
            )

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


@pytest.mark.anyio
class TestValidateDpopRequestIntegration:
    """
    Tests for validate_dpop_request -- the wrapper that combines proof
    validation and access-token validation in one call.
    """

    @pytest.fixture
    def rsa_key(self):
        """Generate an RSA key for testing."""
        return jwk.RSAKey.generate_key()

    @pytest.fixture
    def ec_key(self):
        """Generate an EC key for DPoP proof testing."""
        return jwk.ECKey.generate_key(crv="P-256")

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_validate_dpop_request_return(
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

        result = await authutils.dpop.validate_dpop_request_async(
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
    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_different_http_methods(
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

        result = await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method=http_method,
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
        )

        dpop_claims, _, _ = result
        assert dpop_claims["htm"] == http_method

    @pytest.mark.parametrize("key_type", ["EC", "RSA"])
    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_different_key_types(
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

        result = await authutils.dpop.validate_dpop_request_async(
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

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_access_token_scopes_validation(
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
        result = await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            scope={"openid", "user", "data"},
        )

        dpop_claims, token_claims, client_jwk = result
        assert dpop_claims["htm"] == "GET"

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_validate_dpop_request_secret_parameter(
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
            ) = await authutils.dpop.validate_dpop_request_async(
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

    @pytest.mark.parametrize(
        "as_resource_server, expected_error_cls",
        [
            (True, InvalidNonceErrorResourceServer),
            (False, InvalidNonceErrorAuthorizationServer),
        ],
    )
    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_require_nonce_missing_raises_through_request(
        self,
        mock_validate_jwt,
        mock_get_public_key,
        as_resource_server,
        expected_error_cls,
        rsa_key,
    ):
        """
        Covers the docstring's own TODO ("add unit test(s) for
        as_resource_server") for validate_dpop_request specifically, using
        the require_nonce path.
        """
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        with pytest.raises(expected_error_cls):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                require_nonce=True,
                as_resource_server=as_resource_server,
            )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_require_nonce_invalid_raises_through_request(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        An invalid (not just missing) nonce must also raise through
        the validate_dpop_request wrapper, not only through
        validate_dpop_proof directly.
        """
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key,
            "GET",
            "https://example.com/api/resource",
            access_token,
            nonce="not-a-real-nonce",
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        with pytest.raises(
            (InvalidNonceErrorAuthorizationServer, InvalidNonceErrorResourceServer)
        ):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                require_nonce=True,
            )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_public_key_param_bypasses_jwks_lookup(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        When an explicit `public_key` is supplied, validate_dpop_request
        should use it directly rather than fetching from the issuer's JWKS
        endpoint via get_any_public_key_for_token.
        """
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            public_key=rsa_key.as_pem(),
        )

        mock_get_public_key.assert_not_called()

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_options_param_forwarded_to_validate_jwt(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        The `options` dict should be passed through to the underlying
        token_core.validate_jwt call (e.g. for pyjwt-style decode options).
        """
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }
        custom_options = {"verify_aud": False}

        await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            options=custom_options,
        )

        _, call_kwargs = mock_validate_jwt.call_args
        assert call_kwargs.get("options") == custom_options

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_access_token_scope_missing_raises(
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
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                scope={"openid", "user", "data"},
            )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_access_token_purpose_validation(
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

        result = await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            purpose="access",
        )

        dpop_claims, token_claims, client_jwk = result
        assert token_claims["pur"] == "access"

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_access_token_purpose_mismatch_raises(
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
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                purpose="access",
            )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_denylist_callback_denylisted(
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
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
                denylist_callback=denylist_callback,
            )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_denylist_callback_not_denylisted(
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

        result = await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            denylist_callback=denylist_callback,
        )

        dpop_claims, token_claims, client_jwk = result
        assert dpop_claims["htm"] == "GET"

    @pytest.mark.parametrize(
        "bad_header",
        [pytest.param(None, id="none"), pytest.param("", id="empty")],
    )
    async def test_missing_dpop_header_raises_value_error(self, bad_header):
        """
        A None/empty DPoP header raises ValueError, not AttributeError.

        validate_dpop_request strips an auth scheme prefix from the header, so
        without an explicit guard a None header would crash on .split().
        """
        with pytest.raises(ValueError):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=bad_header,
                access_token="some-token",
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
            )

    @pytest.mark.parametrize(
        "bad_token",
        [pytest.param(None, id="none"), pytest.param("", id="empty")],
    )
    async def test_missing_access_token_raises_value_error(self, bad_token, rsa_key):
        """A None/empty access token raises ValueError before any validation."""
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource"
        )

        with pytest.raises(ValueError):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=bad_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
            )

    async def test_bearer_prefixed_access_token_raises_value_error(self, rsa_key):
        """A full 'Bearer ...' Authorization value is rejected with a clear error."""
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        with pytest.raises(ValueError, match="[Bb]earer"):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token="Bearer " + access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
            )

    @pytest.mark.parametrize("empty", [[], None])
    async def test_empty_issuers_rejected_even_with_public_key(self, empty, rsa_key):
        """
        An empty allowlist is rejected even when the caller supplies the key.

        Supplying public_key skips key discovery, which is the other place the
        allowlist is enforced, so the access token would otherwise be validated
        with nothing constraining its iss claim.
        """
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        with pytest.raises(ValueError, match="issuers"):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=empty,
                public_key=rsa_key.as_pem(),
            )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_issuer_allowlist_passed_to_key_lookup(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        The issuers allowlist reaches key discovery, blocking iss-driven SSRF.

        Key discovery makes outbound HTTP derived from the unverified iss
        claim, so the allowlist must be enforced there rather than only later
        inside validate_jwt.
        """
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
        )

        _, call_kwargs = mock_get_public_key.call_args
        assert call_kwargs.get("allowed_issuers") == ["https://example.com"], (
            "validate_dpop_request must forward the issuer allowlist to key "
            "discovery so an untrusted iss cannot trigger an outbound fetch"
        )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_jti_seen_callback_rejects_replay_through_request(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """jti replay protection is enforced through the combined wrapper too."""
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
        }

        seen = set()

        def jti_seen_callback(jti):
            if jti in seen:
                return True
            seen.add(jti)
            return False

        kwargs = dict(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            jti_seen_callback=jti_seen_callback,
        )

        await authutils.dpop.validate_dpop_request_async(**kwargs)

        with pytest.raises(ValueError, match="replay"):
            await authutils.dpop.validate_dpop_request_async(**kwargs)

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_token_signature_failure_still_rejects_after_key_binding_passes(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        Key binding reads the unverified token, so validate_jwt must still gate.

        cnf.jkt is read before the access token's signature is checked, so this
        confirms a forged-but-correctly-bound token is rejected downstream.
        """
        from authutils.token import core as token_core

        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.side_effect = token_core.JWTError("bad signature")

        with pytest.raises(token_core.JWTError):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
            )

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_denylist_callback_missing_jti_claim(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """
        Confirms validate_dpop_request's own return path doesn't
        assume `jti` is present on token_claims when a denylist_callback is
        supplied. Note: the actual denylist_callback(jti) invocation lives
        inside token_core.validate_jwt, which is mocked out here -- so this
        does not exercise real missing-jti handling there. If that matters,
        it needs coverage in token_core's own test suite instead.
        """
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.return_value = {
            "sub": "test-user",
            "iss": "https://example.com",
            "aud": "test-audience",
            "pur": "access",
            "scope": ["openid", "user"],
            # deliberately no "jti"
        }

        def denylist_callback(jti):
            return False

        result = await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            denylist_callback=denylist_callback,
        )

        dpop_claims, _, _ = result
        assert dpop_claims["htm"] == "GET"

    @patch("authutils.dpop.get_any_public_key_for_token_async", new_callable=AsyncMock)
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_scope_list_is_normalized_to_a_set(
        self, mock_validate_jwt, mock_get_public_key, rsa_key
    ):
        """A scope passed as a list reaches validate_jwt as a set."""
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        mock_get_public_key.return_value = rsa_key.as_pem()
        mock_validate_jwt.return_value = {"sub": "test-user"}

        await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            scope=["openid", "user"],
        )

        assert mock_validate_jwt.call_args.kwargs["scope"] == {"openid", "user"}

    @pytest.mark.parametrize(
        "non_string",
        [pytest.param(12345, id="int"), pytest.param(["a.b.c"], id="list")],
    )
    async def test_non_string_access_token_rejected(self, non_string, rsa_key):
        """A non-string access token raises ValueError, not AttributeError."""
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource"
        )

        with pytest.raises(ValueError, match="must be a string"):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=non_string,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
            )


@pytest.mark.anyio
class TestValidateDpopRequestAsync:
    """
    validate_dpop_request_async must reach the same verdict as the sync
    wrapper, and must not hold the event loop while discovering keys.
    """

    @pytest.fixture
    def rsa_key(self):
        """Generate an RSA key for testing."""
        return jwk.RSAKey.generate_key()

    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_matches_the_sync_wrapper_on_a_valid_request(
        self, mock_validate_jwt, rsa_key
    ):
        """A request that the sync wrapper accepts is accepted identically."""
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )
        mock_validate_jwt.return_value = {"sub": "test-user"}

        kwargs = dict(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
            public_key=rsa_key.as_pem(),
        )

        (
            sync_claims,
            sync_token,
            sync_jwk,
        ) = await authutils.dpop.validate_dpop_request_async(**kwargs)
        (
            async_claims,
            async_token,
            async_jwk,
        ) = await authutils.dpop.validate_dpop_request_async(**kwargs)

        assert async_claims == sync_claims
        assert async_token == sync_token
        assert async_jwk.thumbprint() == sync_jwk.thumbprint()

    @patch("authutils.dpop.get_any_public_key_for_token_async")
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_awaits_async_key_discovery_when_no_public_key_given(
        self, mock_validate_jwt, mock_get_key_async, rsa_key
    ):
        """Discovery goes through the async fetcher, not the blocking one."""
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        async def fake_get_key(token, allowed_issuers=None):
            await anyio.sleep(0)
            return rsa_key.as_pem()

        mock_get_key_async.side_effect = fake_get_key
        mock_validate_jwt.return_value = {"sub": "test-user"}

        await authutils.dpop.validate_dpop_request_async(
            dpop_header=proof,
            access_token=access_token,
            request_method="GET",
            request_url="https://example.com/api/resource",
            issuers=["https://example.com"],
        )

        mock_get_key_async.assert_awaited_once()
        assert mock_get_key_async.await_args.kwargs["allowed_issuers"] == [
            "https://example.com"
        ]

    @patch("authutils.dpop.get_any_public_key_for_token_async")
    async def test_proof_failure_rejects_before_key_discovery(
        self, mock_get_key_async, rsa_key
    ):
        """An invalid proof is refused without triggering any key lookup."""
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        with pytest.raises(ValueError, match="htm mismatch"):
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="DELETE",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
            )

        mock_get_key_async.assert_not_awaited()

    @patch("authutils.dpop.get_any_public_key_for_token_async")
    @patch("authutils.dpop.token_core.validate_jwt")
    async def test_does_not_block_the_event_loop_during_key_discovery(
        self, mock_validate_jwt, mock_get_key_async, rsa_key
    ):
        """Other coroutines keep running while the request awaits key discovery."""
        access_token = _create_signed_access_token(rsa_key)
        proof = authutils.dpop.generate_dpop_proof(
            rsa_key, "GET", "https://example.com/api/resource", access_token
        )

        async def slow_get_key(token, allowed_issuers=None):
            await anyio.sleep(0.05)
            return rsa_key.as_pem()

        mock_get_key_async.side_effect = slow_get_key
        mock_validate_jwt.return_value = {"sub": "test-user"}

        ticks = 0
        stop = False

        async def ticker():
            nonlocal ticks
            while not stop:
                ticks += 1
                await anyio.sleep(0.001)

        async with anyio.create_task_group() as tg:
            tg.start_soon(ticker)
            await authutils.dpop.validate_dpop_request_async(
                dpop_header=proof,
                access_token=access_token,
                request_method="GET",
                request_url="https://example.com/api/resource",
                issuers=["https://example.com"],
            )
            stop = True

        assert ticks > 5, f"event loop appears to have been blocked (ticks={ticks})"


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


def _assert_nonce_error_for_resource_server(err) -> None:
    """Assert a nonce error carries the RFC 9449 resource-server response shape."""
    assert err.code == 401
    assert err.json["error"] == "use_dpop_nonce"
    assert "DPoP-Nonce" in err.error_headers
    assert "WWW-Authenticate" in err.error_headers
    assert len(err.error_headers["DPoP-Nonce"]) > 0
    assert len(err.error_headers["WWW-Authenticate"]) > 0


def _assert_nonce_error_for_authorization_server(err) -> None:
    """Assert a nonce error carries the RFC 9449 authorization-server shape."""
    assert err.code == 400
    assert err.json["error"] == "use_dpop_nonce"
    assert "DPoP-Nonce" in err.error_headers
    assert len(err.error_headers["DPoP-Nonce"]) > 0


def _decode_jwt_header(token: str) -> dict:
    """Decode JWT header without verification, allowing large RSA headers."""
    obj = jws.extract_compact(token.encode("utf-8"), registry=_large_registry())
    return obj.protected


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification, allowing large RSA headers."""
    obj = jws.extract_compact(token.encode("utf-8"), registry=_large_registry())
    return json.loads(obj.payload)


def _large_registry():
    """Build a JWS registry that accepts DPoP-sized headers and algs."""
    return authutils.dpop._LargeHeaderRegistry(
        algorithms=sorted(authutils.dpop.SUPPORTED_DPOP_ALGS)
    )


def _replace_header_field(
    token: str, field: str, value: Any = None, remove: bool = False
) -> str:
    """
    Rebuild a JWT with one header field modified or removed,
    re-encoding the header only (payload and signature bytes are left
    untouched, matching the tamper pattern already used by
    test_algorithm_confusion_injection). Useful for constructing malformed
    DPoP proofs to exercise header-validation failure paths.
    """
    header_b64, payload_b64, signature = token.split(".")
    header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
    header_json = json.loads(base64.urlsafe_b64decode(header_padded).decode("utf-8"))

    if remove:
        header_json.pop(field, None)
    else:
        header_json[field] = value

    new_header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header_json).encode()).rstrip(b"=").decode()
    )
    return f"{new_header_b64}.{payload_b64}.{signature}"


def _replace_payload_field(token: str, field: str, value: Any) -> str:
    """
    Rebuild a JWT with one payload claim modified, leaving the header and
    signature bytes untouched, so that the resulting token is well-formed but
    no longer matches its signature.
    """
    header_b64, payload_b64, signature = token.split(".")
    payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
    payload_json = json.loads(base64.urlsafe_b64decode(payload_padded).decode("utf-8"))
    payload_json[field] = value

    new_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload_json).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{header_b64}.{new_payload_b64}.{signature}"


def _b64url(raw: bytes) -> str:
    """Base64url-encode bytes without padding, as JOSE compact serialization does."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _build_unverifiable_proof(header: dict, claims: dict) -> str:
    """
    Assemble a compact JWS from arbitrary header and claims with a placeholder
    signature. For header-validation tests whose key cannot legitimately sign
    the declared alg (e.g. an oct jwk claiming ES256); header validation runs
    before signature verification, so the signature is never reached.
    """
    return (
        f"{_b64url(json.dumps(header).encode())}."
        f"{_b64url(json.dumps(claims).encode())}.AAAA"
    )


def _minimal_proof_claims(
    method: str = "GET", url: str = "https://example.com/resource"
) -> dict:
    """Build the minimum set of valid, fresh DPoP proof claims."""
    return {
        "jti": os.urandom(8).hex(),
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
    }


def _build_raw_dpop_proof(key: jwk.Key, claims: dict, alg: str = None) -> str:
    """
    Construct a DPoP proof from arbitrary claims (e.g. a
    deliberately stale/future `iat`) rather than going through
    generate_dpop_proof, which always stamps `iat` with the current time.
    Mirrors the manual jwt.encode pattern already used for the stolen-token
    defense test.
    """
    resolved_alg = alg or authutils.dpop._resolve_proof_alg(key)
    header = {
        "typ": "dpop+jwt",
        "alg": resolved_alg,
        "jwk": key.as_dict(private=False),
    }
    return jwt.encode(header, claims, key, registry=_large_registry())
