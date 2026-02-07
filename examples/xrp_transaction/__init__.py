# -*- coding: utf-8 -*-
"""
XRP Transaction Signing Example

Demonstrates how to sign XRP Ledger transactions using a Cryptnox hardware
card for secure key storage and signing.

Usage:
    python xrp_transaction.py --pin YOUR_PIN --destination rXXX...
"""

from .xrp_transaction import (
    # Address derivation
    public_key_to_xrp_address,
    # Network queries
    fetch_account_info,
    fetch_account_sequence,
    fetch_current_ledger_index,
    # Transaction building
    build_payment_transaction,
    encode_transaction_for_signing,
    hash_for_signing,
    # Card interaction
    get_public_key_from_card,
    sign_with_card,
    # Signature processing
    der_to_rs,
    normalize_s,
    rs_to_der,
    normalize_and_der_encode,
    # Transaction finalization
    insert_signature,
    generate_tx_blob,
    calculate_transaction_hash,
    # Verification
    verify_signature_with_xrpl,
    # Entry point
    run_xrp_transaction_example,
)

__all__ = [
    "public_key_to_xrp_address",
    "fetch_account_info",
    "fetch_account_sequence",
    "fetch_current_ledger_index",
    "build_payment_transaction",
    "encode_transaction_for_signing",
    "hash_for_signing",
    "get_public_key_from_card",
    "sign_with_card",
    "der_to_rs",
    "normalize_s",
    "rs_to_der",
    "normalize_and_der_encode",
    "insert_signature",
    "generate_tx_blob",
    "calculate_transaction_hash",
    "verify_signature_with_xrpl",
    "run_xrp_transaction_example",
]
