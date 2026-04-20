"""Main module for SIWE messages construction and validation."""

import secrets
import string
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, List, Optional

import abnf
from abnf.grammars import rfc3986
from eth_account.messages import SignableMessage, _hash_eip191_message, encode_defunct
from pydantic import (
    BaseModel,
    BeforeValidator,
    Field,
    NonNegativeInt,
    field_validator,
    model_validator,
)
from pydantic_core import core_schema
from typing_extensions import Annotated
from web3 import HTTPProvider, Web3
from web3.exceptions import BadFunctionCallOutput, ContractLogicError, Web3RPCError

from .grammars import eip4361
from .parsed import ABNFParsedMessage, RegExpParsedMessage

EIP1271_CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "_message", "type": "bytes32"},
            {"internalType": "bytes", "name": "_signature", "type": "bytes"},
        ],
        "name": "isValidSignature",
        "outputs": [{"internalType": "bytes4", "name": "", "type": "bytes4"}],
        "stateMutability": "view",
        "type": "function",
    }
]
EIP1271_MAGICVALUE = "1626ba7e"

# 32-byte magic suffix appended to EIP-6492 wrapped signatures
EIP6492_MAGIC_SUFFIX = (
    "6492649264926492649264926492649264926492649264926492649264926492"
)

# Deployment bytecode for the off-chain universal signature validator.
# Used via eth_call (no actual deployment) to verify EOA, ERC-1271,
# and EIP-6492 signatures in a single call.
# Source: EIP-6492 reference implementation
EIP6492_VALIDATOR_BYTECODE = "0x608060405234801561001057600080fd5b5060405161069438038061069483398101604081905261002f9161051e565b600061003c848484610048565b9050806000526001601ff35b60007f64926492649264926492649264926492649264926492649264926492649264926100748361040c565b036101e7576000606080848060200190518101906100929190610577565b60405192955090935091506000906001600160a01b038516906100b69085906105dd565b6000604051808303816000865af19150503d80600081146100f3576040519150601f19603f3d011682016040523d82523d6000602084013e6100f8565b606091505b50509050876001600160a01b03163b60000361016057806101605760405162461bcd60e51b815260206004820152601e60248201527f5369676e617475726556616c696461746f723a206465706c6f796d656e74000060448201526064015b60405180910390fd5b604051630b135d3f60e11b808252906001600160a01b038a1690631626ba7e90610190908b9087906004016105f9565b602060405180830381865afa1580156101ad573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101d19190610633565b6001600160e01b03191614945050505050610405565b6001600160a01b0384163b1561027a57604051630b135d3f60e11b808252906001600160a01b03861690631626ba7e9061022790879087906004016105f9565b602060405180830381865afa158015610244573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102689190610633565b6001600160e01b031916149050610405565b81516041146102df5760405162461bcd60e51b815260206004820152603a602482015260008051602061067483398151915260448201527f3a20696e76616c6964207369676e6174757265206c656e6774680000000000006064820152608401610157565b6102e7610425565b5060208201516040808401518451859392600091859190811061030c5761030c61065d565b016020015160f81c9050601b811480159061032b57508060ff16601c14155b1561038c5760405162461bcd60e51b815260206004820152603b602482015260008051602061067483398151915260448201527f3a20696e76616c6964207369676e617475726520762076616c756500000000006064820152608401610157565b60408051600081526020810180835289905260ff83169181019190915260608101849052608081018390526001600160a01b0389169060019060a0016020604051602081039080840390855afa1580156103ea573d6000803e3d6000fd5b505050602060405103516001600160a01b0316149450505050505b9392505050565b600060208251101561041d57600080fd5b508051015190565b60405180606001604052806003906020820280368337509192915050565b6001600160a01b038116811461045857600080fd5b50565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561048c578181015183820152602001610474565b50506000910152565b600082601f8301126104a657600080fd5b81516001600160401b038111156104bf576104bf61045b565b604051601f8201601f19908116603f011681016001600160401b03811182821017156104ed576104ed61045b565b60405281815283820160200185101561050557600080fd5b610516826020830160208701610471565b949350505050565b60008060006060848603121561053357600080fd5b835161053e81610443565b6020850151604086015191945092506001600160401b0381111561056157600080fd5b61056d86828701610495565b9150509250925092565b60008060006060848603121561058c57600080fd5b835161059781610443565b60208501519093506001600160401b038111156105b357600080fd5b6105bf86828701610495565b604086015190935090506001600160401b0381111561056157600080fd5b600082516105ef818460208701610471565b9190910192915050565b828152604060208201526000825180604084015261061e816060850160208701610471565b601f01601f1916919091016060019392505050565b60006020828403121561064557600080fd5b81516001600160e01b03198116811461040557600080fd5b634e487b7160e01b600052603260045260246000fdfe5369676e617475726556616c696461746f72237265636f7665725369676e6572"  # noqa: E501


def is_eip6492_signature(signature: str) -> bool:
    """Check if a hex-encoded signature ends with the EIP-6492 magic suffix."""
    if not isinstance(signature, str):
        return False
    sig = signature[2:] if signature.startswith("0x") else signature
    return len(sig) >= 64 and sig.endswith(EIP6492_MAGIC_SUFFIX)


_ALPHANUMERICS = string.ascii_letters + string.digits


def generate_nonce() -> str:
    """Generate a cryptographically sound nonce."""
    return "".join(secrets.choice(_ALPHANUMERICS) for _ in range(17))


class VerificationError(Exception):
    """Top-level validation and verification exception."""

    pass


class InvalidSignature(VerificationError):
    """The signature does not match the message."""

    pass


class ExpiredMessage(VerificationError):
    """The message is not valid any more."""

    pass


class NotYetValidMessage(VerificationError):
    """The message is not yet valid."""

    pass


class SchemeMismatch(VerificationError):
    """The message does not contain the expected scheme."""

    pass


class DomainMismatch(VerificationError):
    """The message does not contain the expected domain."""

    pass


class NonceMismatch(VerificationError):
    """The message does not contain the expected nonce."""

    pass


class UriMismatch(VerificationError):
    """The message does not contain the expected URI."""

    pass


class ChainIdMismatch(VerificationError):
    """The message does not contain the expected chain ID."""

    pass


class RequestIdMismatch(VerificationError):
    """The message does not contain the expected request ID."""

    pass


class MalformedSession(VerificationError):
    """A message could not be constructed as it is missing certain fields."""

    def __init__(self, missing_fields: Iterable[str]):
        """Construct the exception with the missing fields."""
        self.missing_fields = missing_fields


class VersionEnum(str, Enum):
    """EIP-4361 versions."""

    one = "1"

    def __str__(self):
        """EIP-4361 representation of the enum field."""
        return self.value


def _validate_rfc3986_uri(value: str) -> str:
    """Validate a URI string per RFC 3986."""
    try:
        rfc3986.Rule("URI").parse_all(value)
    except abnf.ParseError as err:
        raise ValueError(f"Invalid URI: {value}") from err
    return value


def _validate_eip4361_rule(rule_name: str, value: str) -> str:
    """Validate a string against an EIP-4361 ABNF rule."""
    try:
        eip4361.Rule(rule_name).parse_all(value)
    except abnf.ParseError as err:
        raise ValueError(f"Invalid {rule_name}: {value}") from err
    return value


AnyUrlStr = Annotated[str, BeforeValidator(_validate_rfc3986_uri)]


def datetime_from_iso8601_string(val: str) -> datetime:
    """Convert an ISO-8601 Datetime string into a valid datetime object."""
    _validate_eip4361_rule("issued-at", val)
    return datetime.fromisoformat(val.replace(".000Z", "Z").replace("Z", "+00:00"))


# NOTE: Do not override the original string, but ensure we do timestamp validation
class ISO8601Datetime(str):
    """A special field class used to denote ISO-8601 Datetime strings."""

    def __init__(self, val: str):
        """Validate ISO-8601 string."""
        # NOTE: `self` is already this class, we are just running our validation here
        datetime_from_iso8601_string(val)

    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        """Create valid pydantic schema object for this type."""
        return core_schema.no_info_after_validator_function(
            cls, core_schema.str_schema()
        )

    @classmethod
    def from_datetime(
        cls, dt: datetime, timespec: str = "milliseconds"
    ) -> "ISO8601Datetime":
        """Create an ISO-8601 formatted string from a datetime object."""
        # NOTE: Only a useful classmethod for creating these objects
        return ISO8601Datetime(
            dt.astimezone(tz=timezone.utc)
            .isoformat(timespec=timespec)
            .replace("+00:00", "Z")
        )

    @property
    def _datetime(self) -> datetime:
        return datetime_from_iso8601_string(self)


def utc_now() -> datetime:
    """Get the current datetime as UTC timezone."""
    return datetime.now(tz=timezone.utc)


class SiweMessage(BaseModel):
    """A Sign-in with Ethereum (EIP-4361) message."""

    scheme: Optional[str] = Field(None, pattern=r"^[a-zA-Z][a-zA-Z0-9+\-.]*$")
    """RFC 3986 URI scheme for the authority that is requesting the signing."""
    domain: str = Field(pattern=r"^[^\s/?#]+$")
    """RFC 4501 dns authority that is requesting the signing."""
    address: str
    """Ethereum address performing the signing conformant to capitalization encoded
    checksum specified in EIP-55 where applicable.
    """
    uri: AnyUrlStr
    """RFC 3986 URI referring to the resource that is the subject of the signing."""
    version: VersionEnum
    """Current version of the message."""
    chain_id: NonNegativeInt
    """EIP-155 Chain ID to which the session is bound, and the network where Contract
    Accounts must be resolved.
    """
    issued_at: ISO8601Datetime
    """ISO 8601 datetime string of the current time."""
    nonce: str = Field(min_length=8, pattern="^[a-zA-Z0-9]+$")
    """Randomized token used to prevent replay attacks, at least 8 alphanumeric
    characters. Use generate_nonce() to generate a secure nonce and store it for
    verification later.
    """
    statement: Optional[str] = None
    """Human-readable ASCII assertion that the user will sign, and it must not contain
    `\n`.
    """
    expiration_time: Optional[ISO8601Datetime] = None
    """ISO 8601 datetime string that, if present, indicates when the signed
    authentication message is no longer valid.
    """
    not_before: Optional[ISO8601Datetime] = None
    """ISO 8601 datetime string that, if present, indicates when the signed
    authentication message will become valid.
    """
    request_id: Optional[str] = None
    """System-specific identifier that may be used to uniquely refer to the sign-in
    request.
    """
    resources: Optional[List[AnyUrlStr]] = None
    """List of information or references to information the user wishes to have resolved
    as part of authentication by the relying party. They are expressed as RFC 3986 URIs
    separated by `\n- `.
    """
    warnings: List[str] = Field(default_factory=list, exclude=True)
    """Non-fatal warnings from validation (e.g. unchecksummed address)."""

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        """Validate the address is well-formed hex with a correct EIP-55 checksum.

        All-lowercase and all-uppercase addresses are accepted (they are valid
        but unchecksummed — a warning is added by the model validator).  Mixed-
        case addresses must pass the EIP-55 checksum or they are rejected.
        """
        if len(v) != 42 or not v.startswith("0x"):
            raise ValueError(f"Invalid Ethereum address format: {v}")
        hex_part = v[2:]
        if not all(c in "0123456789abcdefABCDEF" for c in hex_part):
            raise ValueError(f"Invalid Ethereum address: non-hex characters: {v}")
        if (
            hex_part != hex_part.lower()
            and hex_part != hex_part.upper()
            and not Web3.is_checksum_address(v)
        ):
            raise ValueError("invalid EIP-55 address")
        return v

    @field_validator("statement")
    @classmethod
    def validate_statement(cls, v: Optional[str]) -> Optional[str]:
        """Validate statement using the EIP-4361 grammar."""
        if v is not None:
            _validate_eip4361_rule("statement", v)
        return v

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate request ID using the EIP-4361 grammar."""
        if v is not None:
            _validate_eip4361_rule("request-id", v)
        return v

    @model_validator(mode="after")
    def _check_address_warnings(self) -> "SiweMessage":
        """Add a warning when the address is not EIP-55 checksummed."""
        hex_part = self.address[2:]
        if (
            hex_part == hex_part.lower() or hex_part == hex_part.upper()
        ) and not Web3.is_checksum_address(self.address):
            self.warnings.append(
                f"Address is not EIP-55 checksummed: {self.address}"
            )
        return self

    @classmethod
    def from_message(cls, message: str, abnf: bool = True) -> "SiweMessage":
        """Parse a message in its EIP-4361 format."""
        if abnf:
            parsed_message = ABNFParsedMessage(message=message)
        else:
            parsed_message = RegExpParsedMessage(message=message)

        # TODO There is some redundancy in the checks when deserialising a message.
        return cls(**parsed_message.__dict__)

    def prepare_message(self) -> str:
        """Serialize to the EIP-4361 format for signing.

        It can then be passed to an EIP-191 signing function.

        :return: EIP-4361 formatted message, ready for EIP-191 signing.
        """
        header = f"{self.domain} wants you to sign in with your Ethereum account:"
        if self.scheme:
            header = f"{self.scheme}://{header}"

        uri_field = f"URI: {self.uri}"

        prefix = "\n".join([header, self.address])

        version_field = f"Version: {self.version}"

        chain_field = f"Chain ID: {self.chain_id}"

        nonce_field = f"Nonce: {self.nonce}"

        suffix_array = [uri_field, version_field, chain_field, nonce_field]

        issued_at_field = f"Issued At: {self.issued_at}"
        suffix_array.append(issued_at_field)

        if self.expiration_time:
            expiration_time_field = f"Expiration Time: {self.expiration_time}"
            suffix_array.append(expiration_time_field)

        if self.not_before:
            not_before_field = f"Not Before: {self.not_before}"
            suffix_array.append(not_before_field)

        if self.request_id is not None:
            request_id_field = f"Request ID: {self.request_id}"
            suffix_array.append(request_id_field)

        if self.resources is not None:
            resources_field = "\n".join(
                ["Resources:"] + [f"- {resource}" for resource in self.resources]
            )
            suffix_array.append(resources_field)

        suffix = "\n".join(suffix_array)

        if self.statement is not None:
            prefix = "\n\n".join([prefix, self.statement])
        else:
            prefix += "\n"

        return "\n\n".join([prefix, suffix])

    def verify(
        self,
        signature: Optional[str],
        *,
        scheme: Optional[str] = None,
        domain: Optional[str] = None,
        nonce: Optional[str] = None,
        uri: Optional[str] = None,
        chain_id: Optional[int] = None,
        request_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        provider: Optional[HTTPProvider] = None,
        strict: bool = False,
    ) -> None:
        """Verify the validity of the message and its signature.

        :param signature: Signature to check against the current message.
        :param scheme: Scheme expected to be in the current message.
        :param domain: Domain expected to be in the current message.
        :param nonce: Nonce expected to be in the current message.
        :param uri: URI expected to be in the current message.
        :param chain_id: Chain ID expected to be in the current message.
        :param request_id: Request ID expected to be in the current message.
        :param timestamp: Timestamp used to verify the expiry date and other dates
        fields. Uses the current time by default.
        :param provider: A Web3 provider able to perform a contract check. This is
        required if support for Smart Contract Wallets that implement EIP-1271 or
        EIP-6492 is needed.
        :param strict: When True, requires uri and chain_id parameters to be provided.
        :return: None if the message is valid and raises an exception otherwise
        """
        if strict:
            if uri is None:
                raise VerificationError("Strict mode requires uri parameter")
            if chain_id is None:
                raise VerificationError("Strict mode requires chain_id parameter")
            if domain is None:
                raise VerificationError("Strict mode requires domain parameter")

        message = encode_defunct(text=self.prepare_message())
        w3 = Web3(provider=provider)

        if scheme is not None and self.scheme != scheme:
            raise SchemeMismatch()
        if domain is not None and self.domain != domain:
            raise DomainMismatch()
        if nonce is not None and self.nonce != nonce:
            raise NonceMismatch()
        if uri is not None and str(self.uri) != uri:
            raise UriMismatch()
        if chain_id is not None and self.chain_id != chain_id:
            raise ChainIdMismatch()
        if request_id is not None and self.request_id != request_id:
            raise RequestIdMismatch()

        if timestamp is None:
            verification_time = utc_now()
        else:
            verification_time = timestamp
            if verification_time.tzinfo is None:
                verification_time = verification_time.replace(tzinfo=timezone.utc)
        if (
            self.expiration_time is not None
            and verification_time >= self.expiration_time._datetime
        ):
            raise ExpiredMessage()
        if (
            self.not_before is not None
            and verification_time < self.not_before._datetime
        ):
            raise NotYetValidMessage()

        try:
            address = w3.eth.account.recover_message(message, signature=signature)
        except Exception:
            # Any exception from recover_message (wrong length, bad hex, bad
            # v/r/s, wrong type, None, etc.) means the signature cannot be
            # validated as an EOA signature — fall through to EIP-1271/6492.
            address = None

        if (address is None or address.lower() != self.address.lower()) and (
            provider is None
            or not check_contract_wallet_signature(
                address=self.address,
                message=message,
                signature=signature,
                chain_id=self.chain_id,
                w3=w3,
            )
        ):
            raise InvalidSignature()


def check_contract_wallet_signature(
    address: str,
    message: SignableMessage,
    signature: str,
    chain_id: int,
    w3: Web3,
) -> bool:
    """Verify a signature via EIP-1271 or EIP-6492.

    :param address: The address of the contract
    :param message: The EIP-4361 formatted message
    :param signature: The EIP-1271 or EIP-6492 signature
    :param chain_id: The chain ID from the SIWE message
    :param w3: A Web3 provider able to perform a contract check.
    :return: True if the signature is valid per EIP-1271/EIP-6492.
    """
    try:
        provider_chain_id = w3.eth.chain_id
    except Web3RPCError:
        raise InvalidSignature(
            "Unable to verify contract wallet signature: RPC error"
        ) from None
    if provider_chain_id != chain_id:
        raise ChainIdMismatch(
            f"Provider chain ID {provider_chain_id} does not match "
            f"message chain ID {chain_id}"
        )

    hash_ = _hash_eip191_message(message)

    if is_eip6492_signature(signature):
        return _check_eip6492_signature(address, hash_, signature, w3)

    return _check_eip1271_signature(address, hash_, signature, w3)


def _check_eip6492_signature(
    address: str, hash_: bytes, signature: str, w3: Web3
) -> bool:
    """Verify an EIP-6492 signature using the universal validator bytecode."""
    try:
        raw = signature[2:] if signature.startswith("0x") else signature
        sig_bytes = bytes.fromhex(raw)
    except (AttributeError, TypeError, ValueError):
        return False
    encoded = w3.codec.encode(
        ["address", "bytes32", "bytes"],
        [Web3.to_checksum_address(address), hash_, sig_bytes],
    )
    data = bytes.fromhex(EIP6492_VALIDATOR_BYTECODE[2:]) + encoded
    try:
        result = w3.eth.call({"data": "0x" + data.hex()})
        return result[-1:] == b"\x01"
    except (BadFunctionCallOutput, ContractLogicError, Web3RPCError):
        return False


def _check_eip1271_signature(
    address: str, hash_: bytes, signature: str, w3: Web3
) -> bool:
    """Verify an EIP-1271 signature via isValidSignature contract call."""
    try:
        # For message hashes stored on-chain for Safe wallets, the signatures
        # are always "0x" and should be passed in as-is.
        raw = signature[2:] if signature.startswith("0x") else signature
        sig_bytes = signature if signature == "0x" else bytes.fromhex(raw)
    except (AttributeError, TypeError, ValueError):
        return False
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(address), abi=EIP1271_CONTRACT_ABI
    )
    try:
        response = contract.caller.isValidSignature(hash_, sig_bytes)
        return response.hex() == EIP1271_MAGICVALUE
    except (BadFunctionCallOutput, ContractLogicError, Web3RPCError):
        return False
