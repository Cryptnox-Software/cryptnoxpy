#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRNG Random Data Example with Cryptnox Hardware Wallet smart card

This example demonstrates how to retrieve cryptographically-secure random bytes
directly from the chip's True Random Number Generator (TRNG).

Requirements:
    pip install cryptnox-sdk-py

Usage:
    python trng_random.py --pin <PIN> [--size <SIZE>]

Size rules:
    - Must be between 16 and 64 bytes (inclusive)
    - Must be a multiple of 4
    - Default: 32 bytes
"""

import math
import sys
from collections import Counter
from pathlib import Path

# Allow running directly from the examples folder without pip-installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:
    import cryptnox_sdk_py
except ImportError as e:
    print(f"Error: could not import cryptnox_sdk_py: {e}")
    print("Run from the repository root or install with: pip install cryptnox-sdk-py")
    sys.exit(1)


def get_trng_random(pin: str, size: int = 32) -> bytes:
    """
    Retrieve random bytes from the Cryptnox card TRNG.

    Args:
        pin:  Card PIN code.
        size: Number of random bytes to request (16-64, multiple of 4).

    Returns:
        Random bytes produced by the chip TRNG.

    Raises:
        DataValidationException: If size is outside the allowed range or not a multiple of 4.
        PinException:            If the PIN is incorrect.
        ReaderException:         If no card reader is found.
        CardException:           If no card is detected.
    """
    connection = cryptnox_sdk_py.Connection(0)
    try:
        card = cryptnox_sdk_py.factory.get_card(connection)

        print(f"Connected to card (Serial: {card.serial_number})")

        if pin:
            card.verify_pin(pin)
            print("PIN verified.")

        random_data = card.generate_random_number(size)
        return random_data
    finally:
        connection.disconnect()


def run_entropy_test(pin: str, samples: int = 1_000_000) -> None:
    """
    Collect *samples* bytes from the TRNG, map each to 0-127, and compute
    Shannon entropy.  A healthy TRNG should produce entropy close to 7.0 bits.

    Args:
        pin:     Card PIN code.
        samples: Total number of byte samples to collect (default 1 000 000).
    """
    CHUNK = 64  # maximum bytes per generate_random_number call

    connection = cryptnox_sdk_py.Connection(0)
    try:
        card = cryptnox_sdk_py.factory.get_card(connection)
        print(f"Connected to card (Serial: {card.serial_number})")

        if pin:
            card.verify_pin(pin)
            print("PIN verified.")

        print(f"Collecting {samples:,} byte samples from TRNG (this may take a while)…")
        freq: Counter = Counter()
        collected = 0
        while collected < samples:
            chunk_size = min(CHUNK, samples - collected)
            # chunk_size must be a multiple of 4 and at least 16
            chunk_size = max(16, (chunk_size // 4) * 4)
            raw = card.generate_random_number(chunk_size)
            for byte in raw:
                freq[byte & 0x7F] += 1
            collected += len(raw)
            if collected % 100_000 < CHUNK:
                print(f"  …{collected:,} / {samples:,}", end="\r", flush=True)

        print(f"  Collected {collected:,} samples.              ")
    finally:
        connection.disconnect()

    total = sum(freq.values())
    entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())

    print(f"\nEntropy test results ({total:,} samples, range 0-127):")
    print(f"  Shannon entropy : {entropy:.4f} bits")
    print(f"  Expected (ideal): 7.0000 bits")
    if abs(entropy - 7.0) <= 0.05:
        print("  Result          : PASS — entropy is close to 7.0 bits, TRNG looks healthy.")
    else:
        print(f"  Result          : WARN — entropy deviates by {abs(entropy - 7.0):.4f} bits.")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Retrieve random bytes from the Cryptnox Hardware Wallet smart card TRNG",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Request 32 random bytes (default)
  python trng_random.py --pin 1234

  # Request 64 random bytes
  python trng_random.py --pin 1234 --size 64

  # Run entropy test with 1 million byte samples
  python trng_random.py --pin 1234 --entropy-test

  # Run entropy test with a custom sample count
  python trng_random.py --pin 1234 --entropy-test --samples 500000

Size must be between 16 and 64 bytes and a multiple of 4.
        """
    )
    parser.add_argument("--pin", type=str, default="", help="Card PIN code")
    parser.add_argument(
        "--size",
        type=int,
        default=32,
        help="Number of random bytes to request (16-64, multiple of 4). Default: 32"
    )
    parser.add_argument(
        "--entropy-test",
        action="store_true",
        help="Collect byte samples, map to 0-127, and compute Shannon entropy (expect ~7.0 bits)"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1_000_000,
        help="Number of byte samples to collect for the entropy test. Default: 1000000"
    )
    args = parser.parse_args()

    print("=" * 55)
    print("Cryptnox Hardware Wallet smart card - TRNG Random Data")
    print("=" * 55)

    try:
        if args.entropy_test:
            if args.samples < 1:
                print("Error: --samples must be a positive integer.")
                sys.exit(1)
            run_entropy_test(args.pin, args.samples)
        else:
            if not (16 <= args.size <= 64) or args.size % 4:
                print("Error: size must be between 16 and 64 and a multiple of 4.")
                sys.exit(1)
            print(f"Requesting {args.size} random bytes from TRNG...")
            random_bytes = get_trng_random(args.pin, args.size)
            print(f"\nRandom data ({len(random_bytes)} bytes):")
            print(f"  Hex: {random_bytes.hex()}")
            print(f"  Int: {int.from_bytes(random_bytes, 'big')}")
    except cryptnox_sdk_py.exceptions.ReaderException:
        print("Error: Card reader not found.")
        sys.exit(1)
    except cryptnox_sdk_py.exceptions.CardException as exc:
        print(f"Error: Card error - {exc}")
        sys.exit(1)
    except cryptnox_sdk_py.exceptions.PinException:
        print("Error: Invalid PIN code.")
        sys.exit(1)
    except cryptnox_sdk_py.exceptions.DataValidationException as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    except cryptnox_sdk_py.exceptions.CryptnoxException as exc:
        print(f"Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
