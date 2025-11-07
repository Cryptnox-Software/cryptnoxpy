<p align="center">
  <img src="https://github.com/user-attachments/assets/7613b715-90f3-4855-890e-9bba08add646" height="200" width="200" />
</p>

<h3 align="center">CryptnoxPy - Python SDK for managing smart card wallets</h3>

<br/>
 
[![PyPI version](https://img.shields.io/pypi/v/cryptnoxpy)](https://pypi.org/project/cryptnoxpy)
[![Python versions](https://img.shields.io/pypi/pyversions/cryptnoxpy.svg)](https://pypi.org/project/cryptnoxpy/)
[![Documentation status](https://img.shields.io/badge/docs-latest-blue)](https://cryptnox-software.github.io/cryptnoxpy)
![License](https://img.shields.io/pypi/l/cryptnoxpy)

`cryptnoxpy` is a Python 3 library used to communicate with the **Cryptnox Smartcard Applet**.
It provides a high-level API to manage Cryptnox Hardware Wallet Cards, including initialization,
secure channel setup, seed management, and cryptographic signing.

---

## Supported hardware

- **Cryptnox Smartcards** 💳
- **Standard PC/SC Smartcard Readers**: either USB NFC reader or a USB smartcard reader
  → Readers are also available in the Cryptnox shop.

Get your card and readers here: [shop.cryptnox.com](https://shop.cryptnox.com)

---

## Features

- Establish communication with Cryptnox smartcards
- Initialize and manage card lifecycle
- Secure channel authentication and pairing
- Seed generation and restoration (BIP32 / BIP39 compatibility)
- ECDSA secp256k1 signing for blockchain applications

---

## Installation

```bash
pip install cryptnoxpy
```

Or from source:

```bash
git clone https://github.com/Cryptnox-Software/cryptnoxpy.git
pip install .
```

Requires:
- Python 3.11–3.13
- PC/SC smartcard service (`pcscd`) on Linux

On Linux, ensure the PC/SC service is running:

```bash
sudo systemctl start pcscd
sudo systemctl enable pcscd
```

---

## Quick Usage Examples

### 1. Connect to a Cryptnox Card

```python
import cryptnoxpy

try:
    connection = cryptnoxpy.Connection(0)
    card = cryptnoxpy.factory.get_card(connection)
except cryptnoxpy.ReaderException:
    print("Reader not found at index")
except cryptnoxpy.CryptnoxException as error:
    # Issue loading the card
    print(error)
else:
    # Card is loaded and can be used
    print(f"Card serial number: {card.serial_number}")

```

### 2. Test PIN code

In the PIN verification example below the card must be initialized before calling verify_pin.

```python
import cryptnoxpy

# Connect to the Cryptnox card first
try:
    connection = cryptnoxpy.Connection(0)  # Connect to card at index 0
    card = cryptnoxpy.factory.get_card(connection)
except cryptnoxpy.ReaderException:
    print("Reader not found at index")
except cryptnoxpy.CryptnoxException as error:
    print(f"Error loading card: {error}")
else:
    # Once connected, you can verify the PIN
    pin_to_test = "1234"  # Example PIN
    try:
        card.verify_pin(pin_to_test)
    except cryptnoxpy.PinException:
        print("Invalid PIN code.")
    except cryptnoxpy.DataValidationException:
        print("Invalid PIN length or PIN authentication disabled.")
    except cryptnoxpy.SoftLock:
        print("Card is locked. Please power cycle the card.")
    else:
        print("PIN verified successfully. Card is ready for operations.")
```

### 3. Generate a new seed

In the example below the card must be init before generating a seed.

```python
import binascii
import cryptnoxpy

PIN = "1234"  # or "" if the card was opened via challenge-response

def main():
    try:
        connection = cryptnoxpy.Connection(0)
        card = cryptnoxpy.factory.get_card(connection)
    except cryptnoxpy.ReaderException:
        print("Reader not found at index")
        return
    except cryptnoxpy.CryptnoxException as err:
        print(f"Error loading card: {err}")
        return

    try:
        seed_uid = card.generate_seed(PIN)
    except cryptnoxpy.KeyAlreadyGenerated:
        print("A seed is already generated on this card.")
    except cryptnoxpy.KeyGenerationException as err:
        print(f"Failed to generate seed: {err}")
    else:
        # seed_uid is of type bytes: display in hex for readability
        print("Seed (primary node m) UID:", binascii.hexlify(seed_uid).decode())

if __name__ == "__main__":
    main()
```

---

## Documentation

📚 Full API reference: https://cryptnox-software.github.io/cryptnoxpro

---

## License

- This library is available under **LGPL-3.0+**.  
- For commercial licensing options, contact: **info@cryptnox.ch**
