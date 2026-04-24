# Sign in with Ethereum

This package provides a Python implementation of EIP-4361: Sign in with Ethereum.

## Installation

SIWE can be easily installed in any Python project with pip:

```bash
pip install signinwithethereum
```

The distribution is published as `signinwithethereum`, but the import name remains `siwe`:

```python
from siwe import SiweMessage
```

## Usage

SIWE provides a `SiweMessage` class which implements EIP-4361.

### Parsing a SIWE Message

Parsing is done by initializing a `SiweMessage` object with an EIP-4361 formatted string:

```python
from siwe import SiweMessage
message = SiweMessage.from_message(message=eip_4361_string)
```

Or to initialize a `SiweMessage` as a `pydantic.BaseModel` right away:

```python
message = SiweMessage(domain="login.xyz", address="0x1234...", ...)
```

### Verifying and Authenticating a SIWE Message

Verification and authentication is performed via EIP-191, using the `address` field of the `SiweMessage` as the expected signer. The `verify` method checks message structural integrity, signature address validity, and time-based validity attributes.

Replay protection relies on a **single-use nonce** that your server issues, stores alongside the pending session, passes to `verify`, and consumes on success. Always pass the `nonce` you issued — a signature verified without a nonce check can be replayed.

```python
try:
    message.verify(
        signature="0x...",
        domain="example.com",
        nonce=expected_nonce,  # the nonce your server issued for this session
        uri="https://example.com/login",
        chain_id=1,
        strict=True,
    )
    # Consume the nonce now so it cannot be replayed.
except siwe.VerificationError:
    # Invalid
```

Passing `strict=True` enforces that `domain`, `uri`, `chain_id`, and `nonce` are all supplied. Prefer it for authentication flows.

### Smart-contract wallet signatures (EIP-1271 / EIP-6492)

For signatures produced by contract wallets (Safe, Argent, etc.) rather than
externally owned accounts, pass a `web3` provider to `verify`:

```python
from web3 import HTTPProvider

message.verify(
    signature="0x...",
    provider=HTTPProvider("https://mainnet.infura.io/v3/..."),
)
```

EOA recovery is tried first; if it fails, the signature is checked on-chain via
`isValidSignature(bytes32,bytes)` per EIP-1271. Signatures carrying the EIP-6492
magic suffix are handed to the universal off-chain validator bytecode via
`eth_call`, which covers counterfactual (undeployed) wallets as well as
already-deployed ones. The provider's chain id is checked against the message's
`chainId` before any on-chain call.

Note: this is verification only. EIP-6492 allows a verifier to optionally
submit the factory transaction after a successful check to finalize on-chain
deployment ("side-effectful" verification). This library does not do that — if
you need the wallet actually deployed, submit the factory call yourself.

### Serialization of a SIWE Message

`SiweMessage` instances can also be serialized as their EIP-4361 string representations via the `prepare_message` method:

```python
print(message.prepare_message())
```

## Example

Parsing and verifying a `SiweMessage` is easy:

```python
try:
    message = SiweMessage.from_message(eip_4361_string)
    message.verify(
        signature,
        domain="example.com",
        nonce=expected_nonce,
        uri="https://example.com/login",
        chain_id=1,
        strict=True,
    )
except ValueError:
    # Invalid message format
    print("Authentication attempt rejected.")
except siwe.ExpiredMessage:
    print("Authentication attempt rejected.")
except siwe.DomainMismatch:
    print("Authentication attempt rejected.")
except siwe.NonceMismatch:
    print("Authentication attempt rejected.")
except siwe.InvalidSignature:
    print("Authentication attempt rejected.")

# Message has been verified. Authentication complete. Continue with authorization/other.
```

## Testing

```bash
git submodule update --init
uv sync
uv run pytest
```

## See Also

- [Sign in with Ethereum: TypeScript](https://github.com/signinwithethereum/siwe)
- [SIWE website: siwe.xyz](https://siwe.xyz)
- [EIP-4361 Specification Draft](https://eips.ethereum.org/EIPS/eip-4361)
- [EIP-191 Specification](https://eips.ethereum.org/EIPS/eip-191)

## Disclaimer

Our Python library for Sign in with Ethereum has not yet undergone a formal
security audit. We welcome continued feedback on the usability, architecture,
and security of this implementation.
