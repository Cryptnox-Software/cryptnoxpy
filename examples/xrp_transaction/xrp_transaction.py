#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XRP Transaction Signing Example with Cryptnox Card

This example demonstrates how to:
1. Build an XRP transaction JSON with required fields
2. Encode the transaction for signing using the XRP binary codec
3. Send the digest to the Cryptnox card for signing
4. Receive the signature and construct the signed transaction
5. Generate the final tx_blob ready for submission to the XRP Ledger

Requirements:
    pip install xrpl-py cryptnox-sdk-py

Usage:
    python xrp_transaction.py

Note: This example requires a Cryptnox card with a seed loaded and PIN verified.
"""

import hashlib
import sys
from typing import Dict, Any, Optional, Tuple

# XRP Ledger library for transaction building and serialization
try:
    from xrpl.core.binarycodec import encode, encode_for_signing
    from xrpl.core.addresscodec import encode_classic_address
    XRPL_AVAILABLE = True
except ImportError:
    XRPL_AVAILABLE = False
    print("Warning: xrpl-py not installed. Install with: pip install xrpl-py")

# Cryptnox SDK
try:
    import cryptnox_sdk_py
    from cryptnox_sdk_py import exceptions
    from cryptnox_sdk_py.enums import Derivation, KeyType
    CRYPTNOX_AVAILABLE = True
except ImportError:
    CRYPTNOX_AVAILABLE = False
    print("Warning: cryptnox-sdk-py not installed. Install with: pip install cryptnox-sdk-py")


# =============================================================================
# XRP Transaction Constants
# =============================================================================

# XRP uses secp256k1 curve (same as Bitcoin)
# Derivation path for XRP: m/44'/144'/0'/0/0 (BIP44)
XRP_DERIVATION_PATH = "m/44'/144'/0'/0/0"


# =============================================================================
# XRP Address Derivation Functions
# =============================================================================

def public_key_to_xrp_address(public_key_hex: str) -> str:
    """
    Derive an XRP address from a secp256k1 public key.

    The XRP address derivation process:
    1. SHA-256 hash of the public key bytes
    2. RIPEMD-160 hash of the SHA-256 result (= Account ID)
    3. Encode with XRP's base58check (uses xrpl-py)

    Args:
        public_key_hex: Public key in hexadecimal format (compressed, 33 bytes)

    Returns:
        XRP address string (starts with 'r')

    Example:
        >>> public_key_to_xrp_address("033f6c8455a4c6dfd6536cc61279845a0bb514f2c04d512473d88386bfddbd7be9")
        'rXXX...'
    """
    if not XRPL_AVAILABLE:
        raise ImportError("xrpl-py library required for address derivation")

    # Convert hex to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)

    # Step 1: SHA-256 hash
    sha256_hash = hashlib.sha256(public_key_bytes).digest()

    # Step 2: RIPEMD-160 hash (this is the Account ID)
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    account_id = ripemd160.digest()

    # Step 3: Encode as XRP address using xrpl-py
    xrp_address = encode_classic_address(account_id)

    return xrp_address


# =============================================================================
# XRP Network Query Functions
# =============================================================================

# XRP Testnet and Mainnet RPC endpoints
XRP_TESTNET_URL = "https://s.altnet.rippletest.net:51234/"
XRP_MAINNET_URL = "https://s1.ripple.com:51234/"


def fetch_account_info(account: str, testnet: bool = True) -> Dict[str, Any]:
    """
    Fetch account info from the XRP Ledger, including the current sequence number.

    Args:
        account: XRP address (rXXX...)
        testnet: If True, use Testnet; otherwise use Mainnet

    Returns:
        Dictionary with account info from the ledger

    Raises:
        RuntimeError: If the account is not found or the request fails
    """
    if not XRPL_AVAILABLE:
        raise ImportError("xrpl-py library required for network queries")

    from xrpl.clients import JsonRpcClient
    from xrpl.models.requests import AccountInfo

    url = XRP_TESTNET_URL if testnet else XRP_MAINNET_URL
    client = JsonRpcClient(url)
    response = client.request(AccountInfo(account=account))

    if not response.is_successful():
        error = response.result.get("error", "unknown")
        error_msg = response.result.get("error_message", "")
        raise RuntimeError(f"Failed to fetch account info: {error} {error_msg}")

    return response.result


def fetch_account_sequence(account: str, testnet: bool = True) -> int:
    """
    Fetch the current account sequence number from the XRP Ledger.

    The sequence number must match the next expected value for the account,
    otherwise the transaction will be rejected with tefPAST_SEQ or terPRE_SEQ.

    Args:
        account: XRP address (rXXX...)
        testnet: If True, use Testnet; otherwise use Mainnet

    Returns:
        Current account sequence number

    Raises:
        RuntimeError: If the account is not found (not funded)
    """
    info = fetch_account_info(account, testnet=testnet)
    account_data = info.get("account_data", {})
    return account_data.get("Sequence", 1)


def fetch_current_ledger_index(testnet: bool = True) -> int:
    """
    Fetch the current validated ledger index from the XRP Ledger.

    Useful for setting LastLedgerSequence to prevent stale transactions.

    Args:
        testnet: If True, use Testnet; otherwise use Mainnet

    Returns:
        Current validated ledger index
    """
    if not XRPL_AVAILABLE:
        raise ImportError("xrpl-py library required for network queries")

    from xrpl.clients import JsonRpcClient
    from xrpl.models.requests import Ledger

    url = XRP_TESTNET_URL if testnet else XRP_MAINNET_URL
    client = JsonRpcClient(url)
    response = client.request(Ledger(ledger_index="validated"))

    if not response.is_successful():
        raise RuntimeError("Failed to fetch ledger info")

    return response.result.get("ledger_index", 0)


# =============================================================================
# XRP Transaction Building Functions
# =============================================================================

def build_payment_transaction(
    account: str,
    destination: str,
    amount_drops: str,
    fee_drops: str = "12",
    sequence: int = 1,
    last_ledger_sequence: Optional[int] = None
) -> Dict[str, Any]:
    """
    Build an XRP Payment transaction dictionary.

    Args:
        account: The sender's XRP address (rXXX...)
        destination: The recipient's XRP address
        amount_drops: Amount to send in drops (1 XRP = 1,000,000 drops)
        fee_drops: Transaction fee in drops (default: 12)
        sequence: Account sequence number
        last_ledger_sequence: Optional last ledger sequence for expiration

    Returns:
        Transaction dictionary ready for signing

    Example:
        >>> tx = build_payment_transaction(
        ...     account="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
        ...     destination="rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
        ...     amount_drops="1000000",  # 1 XRP
        ...     sequence=1
        ... )
    """
    tx_dict = {
        "TransactionType": "Payment",
        "Account": account,
        "Destination": destination,
        "Amount": amount_drops,
        "Fee": fee_drops,
        "Sequence": sequence,
    }

    if last_ledger_sequence:
        tx_dict["LastLedgerSequence"] = last_ledger_sequence

    return tx_dict


def encode_transaction_for_signing(tx_dict: Dict[str, Any], public_key_hex: str = "") -> bytes:
    """
    Encode an XRP transaction for signing.

    IMPORTANT: The SigningPubKey MUST be included in the transaction dictionary
    before encoding. The XRP Ledger includes SigningPubKey in the serialized
    data that gets hashed and signed. Without it, the hash will be different
    and the signature will be invalid.

    Args:
        tx_dict: Transaction dictionary
        public_key_hex: The public key to include as SigningPubKey.
            This is required for single-sign transactions.

    Returns:
        Bytes to be hashed for signing
    """
    if not XRPL_AVAILABLE:
        raise ImportError("xrpl-py library required for transaction encoding")

    # Add SigningPubKey to the transaction before encoding.
    # This is critical: xrpl-py's sign() does this internally.
    # The serialized signing data MUST include the SigningPubKey field.
    tx_for_signing = tx_dict.copy()
    if public_key_hex:
        tx_for_signing["SigningPubKey"] = public_key_hex.upper()

    # Use xrpl-py's encode_for_signing which handles the STX prefix
    encoded = encode_for_signing(tx_for_signing)
    return bytes.fromhex(encoded)


def hash_for_signing(encoded_tx: bytes) -> bytes:
    """
    Hash the encoded transaction for signing.

    XRP uses SHA-512 and takes the first 32 bytes (256 bits) as the hash.

    Args:
        encoded_tx: The encoded transaction bytes (with signing prefix)

    Returns:
        32-byte hash ready for ECDSA signing
    """
    full_hash = hashlib.sha512(encoded_tx).digest()
    return full_hash[:32]  # First 32 bytes (256 bits)


# =============================================================================
# Cryptnox Card Signing Functions
# =============================================================================

def get_public_key_from_card(card, derivation_path: str = XRP_DERIVATION_PATH) -> str:
    """
    Get the public key from the Cryptnox card for XRP signing.

    Args:
        card: Connected Cryptnox card instance
        derivation_path: BIP44 derivation path (default: XRP path)

    Returns:
        Public key in hexadecimal format (compressed, 33 bytes)
    """
    # XRP uses secp256k1 (KeyType.K1)
    # First derive to the XRP path
    card.derive(key_type=KeyType.K1, path=derivation_path)

    # Then get the current (derived) key
    return card.get_public_key(
        derivation=Derivation.CURRENT_KEY,
        key_type=KeyType.K1,
        path="",
        compressed=True
    )


def sign_with_card(card, hash_to_sign: bytes, pin: str = "") -> bytes:
    """
    Sign a hash using the Cryptnox card.

    Note: This assumes the key has already been derived to the correct path
    (e.g., via get_public_key_from_card). If not, call card.derive() first.

    Args:
        card: Connected Cryptnox card instance
        hash_to_sign: 32-byte hash to sign
        pin: PIN code if required

    Returns:
        DER-encoded signature
    """
    return card.sign(
        data=hash_to_sign,
        derivation=Derivation.CURRENT_KEY,
        key_type=KeyType.K1,
        pin=pin
    )


def der_to_rs(der_signature: bytes) -> Tuple[int, int]:
    """
    Extract r and s values from a DER-encoded signature.

    DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]

    Args:
        der_signature: DER-encoded signature bytes

    Returns:
        Tuple of (r, s) as integers
    """
    if der_signature[0] != 0x30:
        raise ValueError("Invalid DER signature: missing sequence tag")

    # Skip sequence tag and length
    pos = 2

    # Read r
    if der_signature[pos] != 0x02:
        raise ValueError("Invalid DER signature: missing integer tag for r")
    pos += 1
    r_length = der_signature[pos]
    pos += 1
    r_bytes = der_signature[pos:pos + r_length]
    r = int.from_bytes(r_bytes, 'big')
    pos += r_length

    # Read s
    if der_signature[pos] != 0x02:
        raise ValueError("Invalid DER signature: missing integer tag for s")
    pos += 1
    s_length = der_signature[pos]
    pos += 1
    s_bytes = der_signature[pos:pos + s_length]
    s = int.from_bytes(s_bytes, 'big')

    return r, s


# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_ORDER = SECP256K1_ORDER // 2


def normalize_s(r: int, s: int) -> Tuple[int, int]:
    """
    Normalize the S value to the lower half of the curve order (canonical form).

    XRP requires canonical signatures where S <= N/2 (BIP-62 / BIP-66).
    If S > N/2, replace S with N - S.

    Args:
        r: r component of signature
        s: s component of signature

    Returns:
        Tuple of (r, s) with S normalized
    """
    if s > SECP256K1_HALF_ORDER:
        s = SECP256K1_ORDER - s
    return r, s


# =============================================================================
# Transaction Finalization Functions
# =============================================================================

def insert_signature(
    tx_dict: Dict[str, Any],
    signature_hex: str,
    public_key_hex: str
) -> Dict[str, Any]:
    """
    Insert the signature and public key into the transaction.

    Args:
        tx_dict: Original transaction dictionary
        signature_hex: Signature in XRP format (64 bytes hex)
        public_key_hex: Public key in hex format

    Returns:
        Signed transaction dictionary
    """
    signed_tx = tx_dict.copy()
    signed_tx["TxnSignature"] = signature_hex
    signed_tx["SigningPubKey"] = public_key_hex.upper()
    return signed_tx


def generate_tx_blob(signed_tx: Dict[str, Any]) -> str:
    """
    Generate the final tx_blob for submission to the XRP Ledger.

    Args:
        signed_tx: Signed transaction dictionary

    Returns:
        Hexadecimal tx_blob string ready for submission
    """
    if not XRPL_AVAILABLE:
        raise ImportError("xrpl-py library required for tx_blob generation")

    return encode(signed_tx)


def calculate_transaction_hash(tx_blob: str) -> str:
    """
    Calculate the transaction hash (ID) from the tx_blob.

    Args:
        tx_blob: Hexadecimal tx_blob string

    Returns:
        Transaction hash (ID) in hexadecimal
    """
    # XRP transaction ID uses hash prefix 0x54584E00 ("TXN\0")
    txn_prefix = bytes([0x54, 0x58, 0x4E, 0x00])
    tx_bytes = bytes.fromhex(tx_blob)
    full_hash = hashlib.sha512(txn_prefix + tx_bytes).digest()
    return full_hash[:32].hex().upper()


# =============================================================================
# Verification: Compare with xrpl-py Reference Library
# =============================================================================

def verify_signature_with_xrpl(
    tx_dict: Dict[str, Any],
    signature_hex: str,
    public_key_hex: str
) -> bool:
    """
    Verify the Cryptnox-generated signature using xrpl-py's reference
    ECDSA implementation to ensure correctness.

    This reconstructs the exact verification path that the XRP Ledger uses:
      1. Serialize the transaction (with SigningPubKey) via encode_for_signing
      2. Compute SHA-512 Half of the serialized bytes
      3. Verify the ECDSA signature over that hash

    Args:
        tx_dict: Unsigned transaction dictionary (without TxnSignature)
        signature_hex: DER-encoded signature in hex (from Cryptnox card)
        public_key_hex: Compressed public key in hex

    Returns:
        True if the signature is valid per xrpl-py's reference implementation
    """
    if not XRPL_AVAILABLE:
        return False

    try:
        from ecpy.curves import Curve
        from ecpy.ecdsa import ECDSA
        from ecpy.keys import ECPublicKey
        from xrpl.core.keypairs.helpers import sha512_first_half

        # Reproduce the signing data exactly as xrpl-py / rippled does:
        #   encode_for_signing includes the STX prefix and the SigningPubKey field
        tx_verify = tx_dict.copy()
        tx_verify["SigningPubKey"] = public_key_hex.upper()
        signing_bytes = bytes.fromhex(encode_for_signing(tx_verify))
        digest = sha512_first_half(signing_bytes)

        # Verify with the same curve and signer mode the ledger uses
        curve = Curve.get_curve("secp256k1")
        signer = ECDSA("DER")
        point = curve.decode_point(bytes.fromhex(public_key_hex))
        pub = ECPublicKey(point)

        return signer.verify(digest, bytes.fromhex(signature_hex), pub)
    except (ImportError, ValueError, TypeError):
        return False


# =============================================================================
# Main Example Function
# =============================================================================

def run_xrp_transaction_example(
    pin: str = "",
    destination: str = "",
    amount_xrp: float = 1.0,
    sequence: int = 0,
    debug: bool = False,
    testnet: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Run a complete XRP transaction signing example.

    This function demonstrates the full workflow:
    1. Connect to Cryptnox card
    2. Build XRP payment transaction
    3. Encode and hash for signing
    4. Sign with card
    5. Construct signed transaction
    6. Generate tx_blob

    Args:
        pin: Card PIN code
        destination: Recipient's XRP address (required)
        amount_xrp: Amount to send in XRP
        sequence: Account sequence number (0 = auto-fetch from network)
        debug: Enable debug output
        testnet: If True, use Testnet for auto-fetch; otherwise Mainnet

    Returns:
        Dictionary with transaction details and tx_blob, or None on error
    """
    if not XRPL_AVAILABLE:
        print("Error: xrpl-py library is required. Install with: pip install xrpl-py")
        return None

    if not CRYPTNOX_AVAILABLE:
        print("Error: cryptnox-sdk-py library is required.")
        return None

    if not destination:
        print("Error: --destination is required.")
        return None

    connection = None

    try:
        # =====================================================================
        # Step 1: Connect to Cryptnox Card
        # =====================================================================
        print("=" * 60)
        print("XRP Transaction Signing with Cryptnox Card")
        print("=" * 60)
        print("\n[Step 1] Connecting to Cryptnox card...")

        connection = cryptnox_sdk_py.Connection(0, debug=debug)
        card = cryptnox_sdk_py.factory.get_card(connection, debug=debug)

        print(f"  ✓ Connected to card (Serial: {card.serial_number})")

        # Verify PIN if provided
        if pin:
            print("  → Verifying PIN...")
            card.verify_pin(pin)
            print("  ✓ PIN verified")

        # Check if card has a seed
        if not card.valid_key:
            print("  ✗ Error: Card does not have a seed loaded")
            return None

        # =====================================================================
        # Step 2: Get Public Key from Card
        # =====================================================================
        print("\n[Step 2] Getting public key from card...")
        print(f"  → Derivation path: {XRP_DERIVATION_PATH}")

        public_key_hex = get_public_key_from_card(card, XRP_DERIVATION_PATH)
        print(f"  ✓ Public key: {public_key_hex}")

        # =====================================================================
        # Step 2b: Derive XRP Address from Public Key
        # =====================================================================
        derived_address = public_key_to_xrp_address(public_key_hex)
        print(f"  ✓ Derived XRP address: {derived_address}")

        # The account address MUST match the signing key
        account = derived_address

        # =====================================================================
        # Step 2c: Auto-fetch Sequence Number (if not provided)
        # =====================================================================
        if sequence <= 0:
            network_name = "Testnet" if testnet else "Mainnet"
            print(f"\n[Step 2c] Fetching account sequence from {network_name}...")
            try:
                sequence = fetch_account_sequence(account, testnet=testnet)
                ledger_index = fetch_current_ledger_index(testnet=testnet)
                print(f"  -> Account sequence: {sequence}")
                print(f"  -> Current ledger:   {ledger_index}")
            except RuntimeError as e:
                print(f"  ! Could not fetch sequence: {e}")
                print("  ! The account may not be funded yet.")
                print("  ! Fund it at: https://xrpl.org/resources/dev-tools/xrp-faucets")
                return None

        # =====================================================================
        # Step 3: Build XRP Payment Transaction
        # =====================================================================
        print("\n[Step 3] Building XRP payment transaction...")

        amount_drops = str(int(amount_xrp * 1_000_000))

        tx_dict = build_payment_transaction(
            account=account,
            destination=destination,
            amount_drops=amount_drops,
            fee_drops="12",
            sequence=sequence
        )

        print("  Transaction details:")
        print(f"    • Type: {tx_dict['TransactionType']}")
        print(f"    • From: {tx_dict['Account']}")
        print(f"    • To: {tx_dict['Destination']}")
        print(f"    • Amount: {amount_xrp} XRP ({amount_drops} drops)")
        print(f"    • Fee: {tx_dict['Fee']} drops")
        print(f"    • Sequence: {tx_dict['Sequence']}")

        # =====================================================================
        # Step 4: Encode Transaction for Signing
        # =====================================================================
        print("\n[Step 4] Encoding transaction for signing...")
        print("  -> Including SigningPubKey in serialized data")

        encoded_tx = encode_transaction_for_signing(tx_dict, public_key_hex)
        print(f"  ✓ Encoded transaction ({len(encoded_tx)} bytes)")

        if debug:
            print(f"    Encoded (hex): {encoded_tx.hex()}")

        # =====================================================================
        # Step 5: Hash the Encoded Transaction
        # =====================================================================
        print("\n[Step 5] Hashing transaction (SHA-512, first 32 bytes)...")

        tx_hash = hash_for_signing(encoded_tx)
        print(f"  ✓ Transaction hash: {tx_hash.hex()}")

        # =====================================================================
        # Step 6: Sign with Cryptnox Card
        # =====================================================================
        print("\n[Step 6] Signing with Cryptnox card...")

        der_signature = sign_with_card(card, tx_hash, pin)
        print(f"  ✓ Received DER signature ({len(der_signature)} bytes)")

        if debug:
            print(f"    DER signature: {der_signature.hex()}")

        # =====================================================================
        # Step 7: Convert DER signature to hex
        # =====================================================================
        # The Cryptnox card already returns canonical low-S DER signatures
        # (SIGN command P2=0x00), so no additional normalization is needed.
        print("\n[Step 7] Converting DER signature to hex...")

        signature_hex = der_signature.hex().upper()
        print(f"  ✓ DER signature ({len(signature_hex) // 2} bytes)")

        if debug:
            r, s = der_to_rs(der_signature)
            print(f"    R: {r:064X}")
            print(f"    S: {s:064X}")
            print(f"    S <= N/2: {s <= SECP256K1_HALF_ORDER} (guaranteed by card)")

        # =====================================================================
        # Step 8: Insert Signature into Transaction
        # =====================================================================
        print("\n[Step 8] Inserting signature into transaction (DER hex)...")

        signed_tx = insert_signature(tx_dict, signature_hex, public_key_hex)
        print(f"  ✓ TxnSignature (DER): {signed_tx['TxnSignature'][:32]}...")
        print(f"  ✓ SigningPubKey: {signed_tx['SigningPubKey']}")

        # =====================================================================
        # Step 9: Generate Final tx_blob
        # =====================================================================
        print("\n[Step 9] Generating final tx_blob...")

        tx_blob = generate_tx_blob(signed_tx)
        tx_id = calculate_transaction_hash(tx_blob)

        print(f"  ✓ tx_blob ({len(tx_blob) // 2} bytes):")
        print(f"    {tx_blob[:64]}...")
        print(f"  ✓ Transaction ID: {tx_id}")

        # =====================================================================
        # Step 9: Verify Against xrpl-py Reference Library
        # =====================================================================
        print("\n[Step 9] Comparing signature with xrpl-py reference...")

        is_valid = verify_signature_with_xrpl(tx_dict, signature_hex, public_key_hex)
        if is_valid:
            print("  [PASS] Signature matches xrpl-py reference -- transaction is valid!")
        else:
            print("  [FAIL] Signature does NOT match xrpl-py reference")

        # =====================================================================
        # Summary
        # =====================================================================
        print("\n" + "=" * 60)
        print("TRANSACTION READY FOR SUBMISSION")
        print("=" * 60)
        print(f"\nTransaction ID: {tx_id}")
        print("\ntx_blob (submit this to XRP Ledger):")
        print(tx_blob)

        return {
            "transaction": tx_dict,
            "signed_transaction": signed_tx,
            "tx_blob": tx_blob,
            "transaction_id": tx_id,
            "public_key": public_key_hex,
            "signature": signature_hex
        }

    except exceptions.ReaderException:
        print("\n✗ Error: Card reader not found")
        return None
    except exceptions.CardException as e:
        print(f"\n✗ Error: Card error - {e}")
        return None
    except exceptions.PinException:
        print("\n✗ Error: Invalid PIN code")
        return None
    except exceptions.SeedException:
        print("\n✗ Error: No seed on card. Please load a seed first.")
        return None
    except exceptions.CryptnoxException as e:
        print(f"\n✗ Error: {e}")
        return None
    except (ValueError, TypeError, RuntimeError, ImportError) as e:
        print(f"\n✗ Unexpected error: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return None
    finally:
        if connection:
            print("\n[Cleanup] Disconnecting from card...")
            connection.disconnect()
            print("  ✓ Disconnected")


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="XRP Transaction Signing with Cryptnox Card",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign a 1 XRP transaction
  python xrp_transaction.py --pin 1234 --destination rXXX...

  # Custom amount
  python xrp_transaction.py --pin 1234 --destination rXXX... --amount 10.5

For more information, see README.md
        """
    )

    parser.add_argument(
        "--pin",
        type=str,
        default="",
        help="Card PIN code"
    )
    parser.add_argument(
        "--destination",
        type=str,
        required=True,
        help="Recipient's XRP address (required)"
    )
    parser.add_argument(
        "--amount",
        type=float,
        default=1.0,
        help="Amount to send in XRP"
    )
    parser.add_argument(
        "--sequence",
        type=int,
        default=0,
        help="Account sequence number (0 = auto-fetch from network)"
    )
    parser.add_argument(
        "--mainnet",
        action="store_true",
        help="Use Mainnet instead of Testnet for auto-fetch"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )
    args = parser.parse_args()

    result = run_xrp_transaction_example(
        pin=args.pin,
        destination=args.destination,
        amount_xrp=args.amount,
        sequence=args.sequence,
        debug=args.debug,
        testnet=not args.mainnet
    )

    if not result:
        sys.exit(1)
