#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRNG Random Data Example with Cryptnox Card

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

import sys
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


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Retrieve random bytes from the Cryptnox card TRNG",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Request 32 random bytes (default)
  python trng_random.py --pin 1234

  # Request 64 random bytes
  python trng_random.py --pin 1234 --size 64

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
    args = parser.parse_args()

    if not (16 <= args.size <= 64) or args.size % 4:
        print("Error: size must be between 16 and 64 and a multiple of 4.")
        sys.exit(1)

    print("=" * 50)
    print("Cryptnox Card TRNG Random Data")
    print("=" * 50)
    print(f"Requesting {args.size} random bytes from TRNG...")

    try:
        random_bytes = get_trng_random(args.pin, args.size)
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

    print(f"\nRandom data ({len(random_bytes)} bytes):")
    print(f"  Hex: {random_bytes.hex()}")
    print(f"  Int: {int.from_bytes(random_bytes, 'big')}")


if __name__ == "__main__":
    main()
