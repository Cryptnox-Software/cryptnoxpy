# TRNG Random Data with Cryptnox Card

Retrieve cryptographically-secure random bytes directly from the chip's True Random Number Generator (TRNG).

## Requirements

| Component | Details |
|-----------|---------|
| **Hardware** | Cryptnox card (Basic G1) + PC/SC smart card reader |
| **Python** | `pip install cryptnox-sdk-py` |

## Quick Start

```bash
# Request 32 random bytes (default)
python trng_random.py --pin 1234

# Request 64 random bytes
python trng_random.py --pin 1234 --size 64
```

## Size Rules

| Rule | Value |
|------|-------|
| Minimum | 16 bytes |
| Maximum | 64 bytes |
| Step | Multiple of 4 |

Valid sizes: `16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64`

## Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--pin` | (empty) | Card PIN code |
| `--size` | 32 | Number of random bytes to request |

## Code Example

```python
import cryptnox_sdk_py

connection = cryptnox_sdk_py.Connection(0)
card = cryptnox_sdk_py.factory.get_card(connection)
card.verify_pin("1234")

random_bytes = card.generate_random_number(32)
print(random_bytes.hex())
```

## Error Reference

| Error | Cause | Fix |
|-------|-------|-----|
| `DataValidationException` | Size out of range or not a multiple of 4 | Use a size between 16 and 64, multiple of 4 |
| `PinException` | Wrong PIN code | Provide the correct card PIN |
| `ReaderException` | No card reader found | Connect a PC/SC reader |
| `CardException` | No card detected | Insert the Cryptnox card into the reader |
