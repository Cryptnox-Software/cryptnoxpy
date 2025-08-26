"""
Module containing class for Basic card of 0th generation
"""
from typing import (
    List,
    NamedTuple,
    Tuple
)

from cryptography.hazmat.primitives.asymmetric import ec

from . import base
from .base import Base
from .. import exceptions
from ..binary_utils import path_to_bytes
from ..cryptos import encode_pubkey
from ..enums import (
    AuthType,
    Derivation,
    KeyType,
    SeedSource,
    SlotIndex
)


class BasicG0(Base):
    """
    Class containing functionality for Basic cards of the 0th generation
    """
    select_apdu = [0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x01]
    puk_rule = "15 digits"

    _ALGORITHM = ec.SECP256K1

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialized = False

        self._check_init()

    def change_pairing_key(self, index: int, pairing_key: bytes, puk: str = "") -> None:
        if len(pairing_key) != 32:
            raise exceptions.DataValidationException("Pairing key has to be 32 bytes.")
        if not 0 <= index <= 7:
            raise exceptions.DataValidationException("Index must be between 0 and 7")

        self.connection.send_encrypted([0x80, 0xDA, 0x00, 0x00],
                                       index.to_bytes(1, "big") + pairing_key)

    def derive(self, key_type: KeyType = KeyType.K1, path: str = ""):
        self.get_public_key(Derivation.DERIVE_AND_MAKE_CURRENT, key_type, path=path)

    def dual_seed_public_key(self, pin: str = "") -> bytes:
        raise NotImplementedError("Card doesn't have this functionality")

    def dual_seed_load(self, data: bytes, pin: str = "") -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    @property
    def extended_public_key(self) -> bool:
        return False

    def generate_random_number(self, size: int) -> bytes:
        raise NotImplementedError("Card doesn't have this functionality")

    def generate_seed(self, pin="") -> bytes:
        try:
            gen_resp = self.connection.send_encrypted([0x80, 0xD4, 0x00, 0x00], b"")
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.KeyAlreadyGenerated("The card already has a key generated\n\n"
                                                     "It is not possible to generate another one "
                                                     "without resetting the card") from error
            raise

        if len(gen_resp) != 32:
            raise exceptions.KeyGenerationException("Bad data received during key generation")

        return gen_resp

    def get_public_key(self, derivation: Derivation, key_type: KeyType = KeyType.K1, path: str = "",
                       compressed: bool = True, hexed: bool = True) -> str:
        if not self.valid_key:
            raise exceptions.SeedException()

        derivation = Derivation(derivation)
        key_type = KeyType(key_type)

        if derivation == Derivation.PINLESS_PATH:
            raise exceptions.DerivationSelectionException("This operation doesn't support this "
                                                          "derivation form")

        message = [0x80, 0xC2, derivation + key_type, 1]
        binary_path = path_to_bytes(path) if path else b""
        data = self.connection.send_encrypted(message, binary_path)

        if data[3:5] != b"\x41\x04":
            raise exceptions.ReadPublicKeyException("Invalid data received during public key "
                                                    "reading")

        result = data[4:].hex() if hexed else data[4:]
        if compressed:
            result = encode_pubkey(result, "bin_compressed").hex()

        return result

    def get_public_key_clear(self, derivation: int, path: str = "", compressed: bool = True) -> bytes:
        
        if not self.valid_key:
            raise exceptions.SeedException()

        SELe = [0x80, 0xC2, int(derivation), 1]
        
        if not path:
            pubkeyl, status1, status2 = self.connection.send_apdu(SELe + [0])
        else:
            # Only for testing, should throw error
            path_bin = path_to_bytes(path)
            pubkeyl, status1, status2 = self.connection.send_apdu(SELe + [len(path_bin)] + binary_to_list(path_bin))
        
        # Check if we got an error status
        if status1 != 0x90 or status2 != 0x00:
            raise exceptions.ReadPublicKeyException(f"Card returned error status: {status1:02x}{status2:02x}")
        
        pubkey = bytes(pubkeyl)
        
        # Validate public key format (should start with 0x04 for uncompressed)
        if pubkey[0] != 0x04:
            raise exceptions.ReadPublicKeyException("Bad data received during public key reading")
        
        if not compressed:
            return pubkey
        else:
            pub_bin = encode_pubkey(pubkey, "bin_compressed")
            return pub_bin

    def decrypt(self, p1: int, pubkey: bytes, encrypted_data: bytes = b"", pin: str = "") -> bytes:
        
        # Validate inputs
        if not self.initialized:
            raise exceptions.InitializationException("Card is not initialized")

        if not self.valid_key:
            raise exceptions.SeedException("No seed/key loaded")
        
        if p1 not in [0, 1]:
            raise exceptions.DataValidationException("P1 must be 0 (output symmetric key) or 1 (decrypt data)")
        
        if len(pubkey) != 65:
            raise exceptions.DataValidationException("Public key must be 65 bytes (X9.62 uncompressed format)")
        
        if pubkey[0] != 0x04:
            raise exceptions.DataValidationException("Public key must be in X9.62 uncompressed format (0x04|X|Y)")
        
        # Prepare data based on P1 and authentication status
        data = b""
        
        # Add PIN if provided (right-padded with 0x00 to 9 bytes)
        if pin:
            pin_bytes = pin.encode("ascii")
            if len(pin_bytes) > 9:
                raise exceptions.DataValidationException("PIN too long (max 9 characters)")
            pin_padded = pin_bytes + b"\x00" * (9 - len(pin_bytes))
            data += pin_padded
        
        # Add public key
        data += pubkey
        
        # Add encrypted data if P1=1
        if p1 == 1:
            if not encrypted_data:
                raise exceptions.DataValidationException("Encrypted data required when P1=1")
            
            # Check if data length is multiple of 16 bytes (AES block size)
            if len(encrypted_data) % 16 != 0:
                raise exceptions.DataValidationException("Encrypted data length must be multiple of 16 bytes")
            
            data += encrypted_data
        
        # Validate total data length
        if p1 == 0:
            # P1 = 0: No user key auth, with PIN: 74 bytes, User key auth, no PIN: 65 bytes
            expected_length = 74 if pin else 65
            if len(data) != expected_length:
                raise exceptions.DataValidationException(f"Data length incorrect: {len(data)} bytes (expected {expected_length})")
        else:
            # P1 = 1: No user key auth, with PIN: at least 74 bytes, User key auth, no PIN: at least 65 bytes
            min_length = 74 if pin else 65
            if len(data) < min_length:
                raise exceptions.DataValidationException(f"Data length too short: {len(data)} bytes (minimum {min_length})")
        
        # Send DECRYPT command
        cmd = [0x80, 0xC4, p1, 0x00]
        
        try:
            result = self.connection.send_encrypted(cmd, data)
            return result
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x85:
                raise exceptions.SeedException("No seed/key loaded") from error
            elif error.status[0] == 0x63:
                raise exceptions.PinException("PIN is not correct") from error
            elif error.status[0] == 0x6A and error.status[1] == 0x80:
                raise exceptions.DataValidationException("Data length is not correct") from error
            elif error.status[0] == 0x69 and error.status[1] == 0x82:
                raise exceptions.GenericException("Data input length is far too long") from error
            else:
                raise

    def history(self, index: int = 0) -> NamedTuple:
        raise NotImplementedError("Card doesn't have this functionality")

    @property
    def initialized(self) -> bool:
        return self._initialized

    def load_seed(self, seed: bytes, pin: str = "") -> None:
        try:
            result = self.connection.send_encrypted([0x80, 0xD0, 0x03, 0x00], seed)
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.KeyAlreadyGenerated("The card already has a key generated\n\n"
                                                     "It is not possible to generate another one "
                                                     "without resetting the card") from error
            raise

        if len(result) != 32:
            raise exceptions.KeyGenerationException("Bad data received during key generation")

    @property
    def pin_authentication(self) -> bool:
        return True

    @property
    def pinless_enabled(self) -> bool:
        return False

    def reset(self, puk: str) -> None:
        puk = self.valid_puk(puk)

        message = [0x80, 0xC0, Derivation.CURRENT_KEY, 0x00]

        self.connection.send_encrypted(message, puk.encode("ascii"))
        self.auth_type = AuthType.NO_AUTH

    @property
    def seed_source(self) -> SeedSource:
        raise NotImplementedError("Card doesn't have this functionality")

    def set_pin_authentication(self, status: bool, puk: str) -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def set_pinless_path(self, path: str, puk: str) -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def set_extended_public_key(self, status: bool, puk: str) -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def sign(self, data: bytes, derivation: Derivation, key_type: KeyType = KeyType.K1,
             path: str = "", pin: str = "", filter_eos: bool = False) -> bytes:
        pin = self.valid_pin(pin)
        derivation = Derivation(derivation)
        key_type = KeyType(key_type)

        message = [0x80, 0xC0, derivation + key_type, 0x00]

        derivation_base = (derivation + key_type) & 0x0F
        if derivation_base in (1, 2):
            data += path_to_bytes(path)

        result = self._sign_eos(message, data, pin) if filter_eos else \
            self.connection.send_encrypted(message, data)

        if not result or result[70] != 0x30:
            raise exceptions.DataException("Invalid data received during signature")

        return result[70:]

    @property
    def signing_counter(self) -> int:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_add(self, slot: SlotIndex, data_info: str, public_key: bytes, puk_code: str,
                     cred_id: bytes = b"") -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_delete(self, slot: SlotIndex, puk_code: str) -> None:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_info(self, slot: SlotIndex) -> Tuple[str, str]:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_enabled(self, slot_index: SlotIndex) -> bool:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_challenge_response_nonce(self) -> bytes:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_challenge_response_open(self, slot: SlotIndex, signature: bytes) -> bool:
        raise NotImplementedError("Card doesn't have this functionality")

    def user_key_signature_open(self, slot: SlotIndex, message: bytes, signature: bytes) -> bool:
        raise NotImplementedError("Card doesn't have this functionality")

    def _sign_eos(self, apdu: List[int], data: bytes, pin: str) -> bytes:
        count = 0

        while True:
            result = self.connection.send_encrypted(apdu, data)
            len_r = int(result[73])
            len_s = int(result[75 + len_r])
            if len_r == 32 and len_s == 32:
                break

            count += 1
            if count >= 10:
                raise exceptions.EOSKeyError("The signature wasn't compatible with EOS standard "
                                             "after 10 tries")
            self.verify_pin(pin)

        return result

    @staticmethod
    def valid_puk(puk: str, puk_name: str = "puk") -> str:
        if len(puk) != BasicG0.PUK_LENGTH:
            raise exceptions.DataValidationException(f"The {puk_name} must have "
                                                     f"{BasicG0.PUK_LENGTH} numeric "
                                                     f"characters")
        if not puk.isdigit():
            raise exceptions.DataValidationException(f"The {puk_name} must be numeric.")

        return puk

    @property
    def valid_key(self) -> bool:
        """
        Check if the card has a valid key

        :return: Whether the card has a valid key.
        :rtype: bool
        """
        return self._data and self._data != [0] * 32

    def verify_pin(self, pin: str) -> None:
        pin = self.valid_pin(pin)
        apdu = [0x80, 0x20, 0x00, 0x00]

        self.connection.send_encrypted(apdu, bytes(pin, 'ascii'))

        if not self.open:
            self.auth_type = AuthType.PIN

    def _check_init(self) -> None:
        apdu = [0x80, 0xFE, 0x00, 0x00, 0x01, 0x01]

        try:
            _, code1, code2 = self.connection.send_apdu(apdu)
        except exceptions.DataValidationException:
            return

        self._initialized = code1 == 0x6D and code2 == 0x00

    @property
    def _owner(self) -> base.User:
        message = [0x80, 0xFA, 0x00, 0x00]
        try:
            data = self.connection.send_encrypted(message, bytes([0]))
        except exceptions.CryptnoxException:
            return base.User("", "")

        name_length = data[0]
        name = data[1:name_length + 1].decode("ascii")
        email_length = data[name_length + 1]
        user_list_offset = email_length + 2 + name_length
        email = data[name_length + 2:user_list_offset].decode("ascii")

        return base.User(name, email)
