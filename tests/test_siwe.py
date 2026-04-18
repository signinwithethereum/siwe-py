import json
import os

import abnf
import pytest
from abnf.grammars import rfc3986
from eth_account import Account, messages
from humps import decamelize
from web3 import HTTPProvider
from pydantic import ValidationError

from siwe.grammars.eip4361 import Rule as eip4361_rule
from siwe.siwe import (
    ExpiredMessage,
    InvalidSignature,
    SiweMessage,
    VerificationError,
    datetime_from_iso8601_string,
)

VECTORS = os.path.join(os.path.dirname(__file__), "../test-vectors/vectors")
with open(os.path.join(VECTORS, "parsing/parsing_positive.json"), "r") as f:
    parsing_positive = decamelize(json.load(fp=f))
with open(os.path.join(VECTORS, "parsing/parsing_negative.json"), "r") as f:
    parsing_negative = decamelize(json.load(fp=f))
with open(os.path.join(VECTORS, "parsing/parsing_warnings.json"), "r") as f:
    parsing_warnings = decamelize(json.load(fp=f))
with open(os.path.join(VECTORS, "objects/parsing_negative_objects.json"), "r") as f:
    parsing_negative_objects = decamelize(json.load(fp=f))
with open(os.path.join(VECTORS, "verification/verification_negative.json"), "r") as f:
    verification_negative = decamelize(json.load(fp=f))
with open(os.path.join(VECTORS, "verification/verification_positive.json"), "r") as f:
    verification_positive = decamelize(json.load(fp=f))
with open(os.path.join(VECTORS, "verification/eip1271.json"), "r") as f:
    verification_eip1271 = decamelize(json.load(fp=f))
with open(os.path.join(VECTORS, "grammar/valid_chars.json"), "r") as f:
    valid_chars = json.load(fp=f)
with open(os.path.join(VECTORS, "grammar/invalid_chars.json"), "r") as f:
    invalid_chars = json.load(fp=f)
with open(os.path.join(VECTORS, "grammar/valid_uris.json"), "r") as f:
    valid_uris = json.load(fp=f)
with open(os.path.join(VECTORS, "grammar/invalid_uris.json"), "r") as f:
    invalid_uris = json.load(fp=f)
with open(os.path.join(VECTORS, "grammar/valid_resources.json"), "r") as f:
    valid_resources = json.load(fp=f)
with open(os.path.join(VECTORS, "grammar/invalid_resources.json"), "r") as f:
    invalid_resources = json.load(fp=f)
with open(os.path.join(VECTORS, "objects/message_objects.json"), "r") as f:
    message_objects = decamelize(json.load(fp=f))
with open(os.path.join(VECTORS, "grammar/valid_specification.json"), "r") as f:
    valid_specification = decamelize(json.load(fp=f))

endpoint_uri = "https://cloudflare-eth.com"
try:
    uri = os.environ["WEB3_PROVIDER_URI"]
    if uri != "":
        endpoint_uri = uri
except KeyError:
    pass
sepolia_endpoint_uri = "https://rpc.sepolia.org"
try:
    uri = os.environ["WEB3_PROVIDER_URI_SEPOLIA"]
    if uri != "":
        sepolia_endpoint_uri = uri
except KeyError:
    pass


class TestMessageParsing:
    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_valid_message(self, abnf, test_name, test):
        siwe_message = SiweMessage.from_message(message=test["message"], abnf=abnf)
        for key, value in test["fields"].items():
            v = getattr(siwe_message, key)
            if not (isinstance(v, int) or isinstance(v, list) or v is None):
                v = str(v)
            assert v == value

    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_negative.items()],
    )
    def test_invalid_message(self, abnf, test_name, test):
        with pytest.raises(ValueError):
            SiweMessage.from_message(message=test, abnf=abnf)

    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_negative_objects.items()],
    )
    def test_invalid_object_message(self, test_name, test):
        with pytest.raises(ValidationError):
            SiweMessage(**test)


class TestParsingWarnings:
    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_warnings.items()],
    )
    def test_parsing_with_warnings(self, abnf, test_name, test):
        siwe_message = SiweMessage.from_message(message=test["message"], abnf=abnf)
        for key, value in test["fields"].items():
            v = getattr(siwe_message, key)
            if not (isinstance(v, int) or isinstance(v, list) or v is None):
                v = str(v)
            assert v == value
        assert len(siwe_message.warnings) == test["expected_warnings"]


class TestMessageGeneration:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_valid_message(self, test_name, test):
        siwe_message = SiweMessage(**test["fields"])
        assert siwe_message.prepare_message() == test["message"]


class TestMessageVerification:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_positive.items()],
    )
    def test_valid_message(self, test_name, test):
        siwe_message = SiweMessage(**test)
        timestamp = (
            datetime_from_iso8601_string(test["time"]) if "time" in test else None
        )
        siwe_message.verify(test["signature"], timestamp=timestamp)

    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_eip1271.items()],
    )
    def test_eip1271_message(self, test_name, test):
        if test_name == "loopring":
            pytest.skip()
        provider = HTTPProvider(endpoint_uri=endpoint_uri)
        siwe_message = SiweMessage.from_message(message=test["message"])
        siwe_message.verify(test["signature"], provider=provider)

    def test_safe_wallet_message(self):
        message = "localhost:3000 wants you to sign in with your Ethereum account:\n0x54D97AEa047838CAC7A9C3e452951647f12a440c\n\nPlease sign in to verify your ownership of this wallet\n\nURI: http://localhost:3000\nVersion: 1\nChain ID: 11155111\nNonce: gDj8rv7VVxN\nIssued At: 2024-10-10T08:34:03.152Z\nExpiration Time: 2024-10-13T08:34:03.249112Z"
        signature = "0x"
        # Use a Sepolia RPC node since the signature is generated on Sepolia testnet
        # instead of mainnet like other EIP-1271 tests.
        provider = HTTPProvider(endpoint_uri=sepolia_endpoint_uri)
        siwe_message = SiweMessage.from_message(message=message)
        # Use a timestamp within the message's validity window
        timestamp = datetime_from_iso8601_string("2024-10-11T08:34:03.152Z")
        siwe_message.verify(signature, timestamp=timestamp, provider=provider)

    @pytest.mark.parametrize(
        "provider", [HTTPProvider(endpoint_uri=endpoint_uri), None]
    )
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_negative.items()],
    )
    def test_invalid_message(self, provider, test_name, test):
        if test_name in [
            "invalidexpiration_time",
            "invalidnot_before",
            "invalidissued_at",
        ]:
            with pytest.raises(ValidationError):
                siwe_message = SiweMessage(**test)
            return
        siwe_message = SiweMessage(**test)
        domain_binding = test.get("domain_binding")
        match_nonce = test.get("match_nonce")
        timestamp = (
            datetime_from_iso8601_string(test["time"]) if "time" in test else None
        )
        with pytest.raises(VerificationError):
            siwe_message.verify(
                test.get("signature"),
                scheme=test.get("scheme"),
                domain=domain_binding,
                nonce=match_nonce,
                timestamp=timestamp,
                provider=provider,
            )


class TestMessageRoundTrip:
    account = Account.create()

    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_message_round_trip(self, test_name, test):
        message = SiweMessage(**test["fields"])
        message.address = self.account.address
        signature = self.account.sign_message(
            messages.encode_defunct(text=message.prepare_message())
        ).signature
        message.verify(signature)

    def test_schema_generation(self):
        # NOTE: Needed so that FastAPI/OpenAPI json schema works
        SiweMessage.model_json_schema()


class TestVerifyHardening:
    account = Account.create()

    def _build(self, **overrides):
        fields = dict(
            domain="ex.com",
            address=self.account.address,
            uri="https://ex.com",
            version="1",
            chain_id=1,
            nonce="12345678",
            issued_at="2024-01-01T00:00:00Z",
        )
        fields.update(overrides)
        return SiweMessage(**fields)

    def test_chain_id_zero_round_trip(self):
        m = self._build(chain_id=0)
        assert "Chain ID: 0" in m.prepare_message()
        parsed = SiweMessage.from_message(m.prepare_message())
        assert parsed.chain_id == 0

    @pytest.mark.parametrize("bad_sig", ["0xZZ", "0x1", "", "0x", "not-a-signature"])
    def test_verify_rejects_malformed_signature(self, bad_sig):
        m = self._build()
        with pytest.raises(InvalidSignature):
            m.verify(bad_sig)

    def test_verify_rejects_none_signature(self):
        m = self._build()
        with pytest.raises(InvalidSignature):
            m.verify(None)

    def test_verify_accepts_naive_timestamp(self):
        from datetime import datetime

        m = self._build(expiration_time="2020-01-01T00:00:00Z")
        with pytest.raises(ExpiredMessage):
            m.verify("0x" + "00" * 65, timestamp=datetime(2025, 1, 1))


def _get_abnf_rule(rule_name):
    """Get the ABNF rule parser for a given rule name."""
    if rule_name == "statement":
        return eip4361_rule(rule_name)
    return rfc3986.Rule(rule_name)


class TestValidChars:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in valid_chars.items()],
    )
    def test_valid_char(self, test_name, test):
        rule = _get_abnf_rule(test["rule"])
        node = rule.parse_all(test["input"])
        assert node is not None

class TestInvalidChars:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in invalid_chars.items()],
    )
    def test_invalid_char(self, test_name, test):
        rule = _get_abnf_rule(test["rule"])
        with pytest.raises(abnf.ParseError):
            rule.parse_all(test["input"])


XFAIL_VALID_URIS_ABNF = {
    "uri-js mixed IPv4address & reg-name: uri://10.10.10.10.example.com/en/process",
    "IPv4address leading zeros: uri://[::000.000.010.001]",
    "IPv4address max value: uri://[::001.099.200.255]",
}
XFAIL_VALID_URIS_REGEX = {
    "uri-js mixed IPv4address & reg-name: uri://10.10.10.10.example.com/en/process",
    "IPv4address leading zeros: uri://[::000.000.010.001]",
    "IPv4address max value: uri://[::001.099.200.255]",
}


class TestValidUris:
    @pytest.mark.parametrize("abnf_mode", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in valid_uris.items()],
    )
    def test_valid_uri(self, abnf_mode, test_name, test):
        xfail_set = XFAIL_VALID_URIS_ABNF if abnf_mode else XFAIL_VALID_URIS_REGEX
        if test_name in xfail_set:
            pytest.xfail("Known parser limitation for this URI")
        siwe_message = SiweMessage.from_message(message=test["msg"], abnf=abnf_mode)
        assert siwe_message is not None


class TestInvalidUris:
    @pytest.mark.parametrize("abnf_mode", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in invalid_uris.items()],
    )
    def test_invalid_uri(self, abnf_mode, test_name, test):
        with pytest.raises((ValueError, ValidationError)):
            SiweMessage.from_message(message=test, abnf=abnf_mode)


XFAIL_VALID_RESOURCES_ABNF = {
    "Resources IP-literal: [uri://10.10.10.10.example.com/en/process, uri://[2606:2800:220:1:248:1893:25c8:1946]/test]",
}
XFAIL_VALID_RESOURCES_REGEX = {
    "Resources IP-literal: [uri://10.10.10.10.example.com/en/process, uri://[2606:2800:220:1:248:1893:25c8:1946]/test]",
}


class TestValidResources:
    @pytest.mark.parametrize("abnf_mode", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in valid_resources.items()],
    )
    def test_valid_resource(self, abnf_mode, test_name, test):
        xfail_set = (
            XFAIL_VALID_RESOURCES_ABNF if abnf_mode else XFAIL_VALID_RESOURCES_REGEX
        )
        if test_name in xfail_set:
            pytest.xfail("Known parser limitation for this URI in resources")
        siwe_message = SiweMessage.from_message(message=test["msg"], abnf=abnf_mode)
        assert siwe_message.resources == test["resources"]


class TestInvalidResources:
    @pytest.mark.parametrize("abnf_mode", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in invalid_resources.items()],
    )
    def test_invalid_resource(self, abnf_mode, test_name, test):
        with pytest.raises((ValueError, ValidationError)):
            SiweMessage.from_message(message=test, abnf=abnf_mode)


class TestMessageObjects:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in message_objects.items()],
    )
    def test_message_object(self, test_name, test):
        if test["error"] == "none":
            siwe_message = SiweMessage(**test["msg"])
            assert siwe_message is not None
            assert len(siwe_message.warnings) == test.get("expected_warnings", 0)
        else:
            with pytest.raises((ValueError, ValidationError)):
                SiweMessage(**test["msg"])


XFAIL_VALID_SPEC_ABNF = set()
XFAIL_VALID_SPEC_REGEX = set()


class TestValidSpecification:
    @pytest.mark.parametrize("abnf_mode", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in valid_specification.items()],
    )
    def test_valid_specification(self, abnf_mode, test_name, test):
        xfail_set = XFAIL_VALID_SPEC_ABNF if abnf_mode else XFAIL_VALID_SPEC_REGEX
        if test_name in xfail_set:
            pytest.xfail("Known parser limitation for this edge case")
        siwe_message = SiweMessage.from_message(message=test["msg"], abnf=abnf_mode)
        for key, value in test["items"].items():
            assert getattr(siwe_message, key) == value
