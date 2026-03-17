# TRNG Random Data with Cryptnox Hardware Wallet smart card

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

# Run entropy quality test (1 million byte samples)
python trng_random.py --pin 1234 --entropy-test
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
| `--entropy-test` | off | Run Shannon entropy quality test |
| `--samples` | 1000000 | Number of byte samples for the entropy test |

## Entropy Quality Test

The `--entropy-test` flag verifies the statistical quality of the TRNG output:

1. Collects `--samples` bytes from the TRNG (default: 1,000,000)
2. Maps each byte to the range 0–127 (`byte & 0x7F`)
3. Computes the **Shannon entropy** of the distribution

A uniform distribution over 128 values has a theoretical maximum entropy of
**7.0 bits** (`log2(128)`). If the measured entropy is close to 7.0 bits, the
TRNG is producing high-quality random data.

```bash
# Run with default 1 million samples
python trng_random.py --pin 1234 --entropy-test

# Run with a custom sample count
python trng_random.py --pin 1234 --entropy-test --samples 500000
```

Example output:

```
Entropy test results (1,000,064 samples, range 0-127):
  Shannon entropy : 6.9998 bits
  Expected (ideal): 7.0000 bits
  Result          : PASS — entropy is close to 7.0 bits, TRNG looks healthy.
```

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
