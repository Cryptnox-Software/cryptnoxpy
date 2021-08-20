"""
Module containing class for Basic card of 1st generation
"""
from collections import namedtuple
from typing import (
    Dict,
    NamedTuple,
    Tuple
)

from cryptography.hazmat.primitives.asymmetric import ec

from . import base
from . import basic
from .base import AuthType
from .. import exceptions
from ..binary_utils import path_to_bytes
from ..cryptos import encode_pubkey
from ..enums import (
    Derivation,
    KeyType,
    SeedSource,
    SlotIndex
)


class BasicG1(basic.Basic):
    """
    Class containing functionality for Basic cards of the 1st generation
    """
    select_apdu = [0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12]
    puk_rule = "12 digits and/or letters"

    _ALGORITHM = ec.SECP256R1
    PUK_LENGTH = 12

    _INITIALIZATION_FLAG = int("01000000", 2)
    _SEED_FLAG = int("00100000", 2)
    _PIN_AUTH_FLAG = int("00010000", 2)
    _PINLESS_FLAG = int("00001000", 2)
    _EXTENDED_PUBLIC_KEY = int("00000100", 2)

    def change_pairing_key(self, index: int, pairing_key: bytes, puk: str = "") -> None:
        if len(pairing_key) != 32:
            raise exceptions.DataValidationException("Pairing key has to be 32 bytes.")
        if index != 0:
            raise exceptions.DataValidationException("Index must be 0")
        puk = self.valid_puk(puk)

        puk = self.valid_puk(puk)
        try:
            self.connection.send_encrypted([0x80, 0xDA, index, 0x00],
                                           pairing_key + puk.encode("ascii"))
        except exceptions.PinException as error:
            raise exceptions.PukException(error.number_of_retries, "Wrong puk") from error

    def derive(self, key_type: KeyType = KeyType.K1, path: str = ""):
        message = [0x80, 0xD1, 0x08, 0x00]
        binary_path = path_to_bytes(path) if path else b""
        self.connection.send_encrypted(message, binary_path)

    def dual_seed_public_key(self, pin: str = "") -> bytes:
        if self.auth_type == AuthType.PIN:
            pin = self.valid_pin(pin)

        result = self.connection.send_encrypted([0x80, 0xD0, 0x04, 0x00], pin.encode("ascii"))

        if len(result) < 65:
            raise exceptions.DataException("Bad data received. Dual seed read card public key")

        return result

    def dual_seed_load(self, data: bytes, pin: str = "") -> None:
        if self.auth_type == AuthType.PIN:
            pin = self.valid_pin(pin)

        self.connection.send_encrypted([0x80, 0xD0, 0x05, 0x00], data + pin.encode("ascii"))

        if not self.open:
            self.auth_type = AuthType.PIN

    @property
    def extended_public_key(self) -> bool:
        return bool(self._data[1] & BasicG1._EXTENDED_PUBLIC_KEY)

    def generate_random_number(self, size: int) -> bytes:
        try:
            size = int(size)
        except ValueError:
            raise exceptions.DataValidationException("Checksum has to be an integer")
        if 16 > size > 64 or size % 4:
            raise exceptions.DataValidationException("Checksum value must be between 4 and 8.")

        return self.connection.send_encrypted([0x80, 0xD3, size, 0x00], b"")

    def generate_seed(self, pin: str = "") -> bytes:
        if self.auth_type == AuthType.PIN:
            pin = self.valid_pin(pin)

        message = [0x80, 0xD4, 0x00, 0x00]

        try:
            result = self.connection.send_encrypted(message, pin.encode("ascii"))
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.KeyAlreadyGenerated("The card already has a key generated\n\n"
                                                     "It is not possible to generate another one "
                                                     "without resetting the card") from error
            raise

        if result and not self.open:
            self.auth_type = AuthType.PIN

        return result

    def get_public_key(self, derivation: Derivation,
                       key_type: KeyType = KeyType.K1, path: str = "",
                       compressed: bool = True) -> str:
        key_type = KeyType(key_type)
        derivation = Derivation(derivation)

        if derivation in (Derivation.PINLESS_PATH,
                          Derivation.DERIVE_AND_MAKE_CURRENT):
            raise exceptions.DerivationSelectionException("This operation doesn't support "
                                                          "this derivation form")

        message = [0x80, 0xC2, derivation + key_type, 1]
        binary_path = path_to_bytes(path) if path else b""
        data = self.connection.send_encrypted(message, binary_path)

        result = data.hex()
        if compressed:
            result = encode_pubkey(result, "bin_compressed").hex()

        return result

    def history(self, index: int = 0) -> NamedTuple:
        Entry = namedtuple('HistoryEntry', ['signing_counter', 'hashed_data'])

        result = self.connection.send_encrypted([0x80, 0xFB, index, 0x00], b"")

        return Entry(int.from_bytes(result[:4], "big"), result[4:])

    @property
    def initialized(self) -> bool:
        return bool(self._data[1] & BasicG1._INITIALIZATION_FLAG)

    def load_seed(self, seed: bytes, pin: str = "") -> None:
        if self.auth_type == AuthType.PIN:
            pin = self.valid_pin(pin) or ""

        try:
            self.connection.send_encrypted([0x80, 0xD0, 0x03, 0x00], seed + pin.encode("ascii"))
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.KeyAlreadyGenerated("The card already has a key generated\n\n"
                                                     "It is not possible to generate another one "
                                                     "without resetting the card") from error
            raise

        if not self.open:
            self.auth_type = AuthType.PIN

    @property
    def pin_authentication(self) -> bool:
        return bool(self._data[1] & BasicG1._PIN_AUTH_FLAG)

    @property
    def pinless_enabled(self) -> bool:
        return bool(self._data[1] & BasicG1._PINLESS_FLAG)

    def reset(self, puk: str) -> None:
        puk = self.valid_puk(puk)
        try:
            self.connection.send_encrypted([0x80, 0xFD, 0, 0], puk.encode("ascii"))
        except exceptions.PinException as error:
            raise exceptions.PukException(error.number_of_retries, "Wrong puk") from error

        self.auth_type = AuthType.NO_AUTH

    @property
    def seed_source(self) -> SeedSource:
        return SeedSource(self._info[0])

    def set_pin_authentication(self, status: bool, puk: str) -> None:
        puk = self.valid_puk(puk)
        status = int(not status).to_bytes(1, "big")

        try:
            self.connection.send_encrypted([0x80, 0xC3, 0, 0], status + puk.encode("ascii"))
        except exceptions.PinException as error:
            raise exceptions.PukException(error.number_of_retries, "Wrong puk") from error
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x86:
                raise exceptions.PinAuthenticationException("PIN can't be set without user key.")
            raise

    def set_pinless_path(self, path: bytes, puk: str) -> None:
        puk = self.valid_puk(puk)

        try:
            self.connection.send_encrypted([0x80, 0xC1, 0, 0], puk.encode("ascii") + path)
        except exceptions.PinException as error:
            raise exceptions.PukException(error.number_of_retries, "Wrong puk") from error
        except exceptions.GenericException as error:
            if error.status[0] == 0x6A and error.status[1] == 0x80:
                raise exceptions.DataValidationException("Path length not multiple of 4")
            if error.status[0] == 0x69:
                if error.status[1] == 0x83:
                    raise exceptions.DataValidationException("Path doesn't start with EIP1581 path")
                if error.status[1] == 0x85:
                    raise exceptions.DataValidationException("No seed or extended key")

            raise

    def set_extended_public_key(self, status: bool, puk: str) -> None:
        puk = self.valid_puk(puk)
        status = int(status).to_bytes(1, "big")

        try:
            self.connection.send_encrypted([0x80, 0xC3, 0, 0], status + puk.encode("ascii"))
        except exceptions.PinException as error:
            raise exceptions.PukException(error.number_of_retries, "Wrong puk") from error
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x85:
                raise exceptions.SeedException("Seed not found")
            raise

    @property
    def signing_counter(self) -> int:
        result = self._info
        position = 1 + int(result[1]) + int(result[result[1] + 2]) + 2

        return int.from_bytes(result[position:], "big")

    @property
    def user_data(self) -> bytes:
        try:
            result = self.connection.send_encrypted([0x80, 0xFA, 0x00, 0x01], b"", True)
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x85:
                raise exceptions.SecureChannelException("Command may need a secured channel")
            raise

        return result

    @user_data.setter
    def user_data(self, value: bytes) -> None:
        try:
            self.connection.send_encrypted([0x80, 0xFC, 0x00, 0x00], value)
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x85:
                raise exceptions.CardClosedException("Card needs to be opened for this operation")
            if error.status[0] == 0x67 and error.status[1] == 0x00:
                raise exceptions.DataValidationException("Value to large to write")

            raise

    def user_key_add(self, slot: SlotIndex, data_info: str, public_key: bytes, puk_code: str,
                     cred_id: bytes = b"") -> None:
        data_info_length = 64
        puk_code = self.valid_puk(puk_code)
        if len(data_info) > data_info_length:
            raise exceptions.DataValidationException(f"Data info can't be longer than "
                                                     f"{data_info_length} characters")
        data_info += "\0" * (data_info_length - len(data_info))

        data = bytes([slot]) + data_info.encode("ascii")
        if slot == SlotIndex.FIDO:
            if not cred_id:
                raise exceptions.DataValidationException("Cred id is required")
            data += bytes([len(cred_id)]) + cred_id
        data += public_key + puk_code.encode("ascii")

        try:
            self.connection.send_encrypted([0x80, 0xD5, 0x00, 0x00], data)
        except exceptions.PinException as error:
            raise exceptions.PukException(error.number_of_retries)
        except exceptions.GenericException as error:
            if error.status == 0x6A80:
                raise exceptions.DataValidationException("Invalid slot index")
            if error.status == 0x6984:
                raise exceptions.DataValidationException("Invalid public key")
            if error.status == 0x6986:
                raise exceptions.DataValidationException("Slot not empty")
            if error.status == 0x6700:
                raise exceptions.DataValidationException("Invalid data length")
            raise
        self._data[3] = BasicG1._set_bit(self._data[3], slot - 1)

    def user_key_delete(self, slot: SlotIndex, puk_code: str) -> None:
        puk_code = self.valid_puk(puk_code)
        data = bytes([slot.value]) + puk_code.encode("ascii")
        try:
            self.connection.send_encrypted([0x80, 0xD7, 0x00, 0x00], data)
        except exceptions.PinException as error:
            raise exceptions.PukException(error.number_of_retries)
        except exceptions.GenericException as error:
            if error.status == 0x6A80:
                raise exceptions.DataValidationException("Invalid slot index")
            if error.status == 0x6700:
                raise exceptions.DataValidationException("Invalid data length")
            if error.status == 0x6986:
                raise exceptions.DataValidationException("Slot empty")
            raise

        self._data[3] = BasicG1._clear_bit(self._data[3], slot - 1)

    def user_key_info(self, slot: SlotIndex) -> Tuple[str, str]:
        try:
            result = self.connection.send_encrypted([0x80, 0xFA, int(slot), 0x00], b"", True)
        except exceptions.GenericException as error:
            if error.status == 0x6985:
                raise exceptions.SecureChannelException("Command may need a secured channel")
            raise

        return result[:64].decode("ascii"), result[64:].hex()

    def user_key_enabled(self, slot_index: SlotIndex):
        return bool(self._data[3] & pow(2, slot_index - 1))

    def user_key_challenge_response_nonce(self) -> bytes:
        result = self.connection.send_encrypted([0x80, 0xD6, 0x01, 0x00], b"")

        return result

    def user_key_challenge_response_open(self, slot: SlotIndex, signature: bytes) -> bool:
        data = bytes([slot.value]) + signature
        try:
            result = self.connection.send_encrypted([0x80, 0xD6, 0x02, 0x00], data)
        except exceptions.GenericException as error:
            if error.status == 0x6A80:
                raise exceptions.DataValidationException("Invalid slot index")
            if error.status == 0x6985:
                raise exceptions.DataValidationException("Nonce not found")
            raise

        result = int.from_bytes(result, "big") == 0x01

        if result and not self.open:
            self.auth_type = AuthType.USER_KEY

        return result

    def user_key_signature_open(self, slot: SlotIndex, message: bytes, signature: bytes) -> bool:
        data = bytes([slot.value]) + message + signature
        try:
            result = self.connection.send_encrypted([0x80, 0xD6, 0x00, 0x00], data)
        except exceptions.GenericException as error:
            if error.status == 0x6A80:
                raise exceptions.DataValidationException("Invalid slot index")
            raise

        return int.from_bytes(result, "big") == 0x01

    def sign(self, data: bytes, derivation: Derivation = Derivation.CURRENT_KEY,
             key_type: KeyType = KeyType.K1, path: str = "", pin: str = "",
             filter_eos: bool = False) -> bytes:
        derivation = Derivation(derivation)
        key_type = KeyType(key_type)

        if derivation == Derivation.DERIVE_AND_MAKE_CURRENT or \
                (derivation == Derivation.PINLESS_PATH and key_type == KeyType.R1):
            raise exceptions.DerivationSelectionException("This operation doesn't support "
                                                          "this derivation form")

        signal = [0x80, 0xC0, derivation + key_type, 0x01 if filter_eos else 0x00]

        derivation_base = (derivation + key_type) & 0x0F
        if derivation_base in (1, 2):
            data += path_to_bytes(path)

        if pin:
            data += bytes(pin, 'ascii')

        result = self.connection.send_encrypted(signal, data)

        if not result or result[0] != 0x30:
            self.auth_type = AuthType.NO_AUTH
            raise exceptions.DataException("Invalid data received during signature")

        return result

    @property
    def valid_key(self) -> bool:
        return bool(self._data[1] & BasicG1._SEED_FLAG)

    @staticmethod
    def valid_puk(puk: str, puk_name: str = "puk") -> str:
        if len(puk) != BasicG1.PUK_LENGTH:
            raise exceptions.DataValidationException(f"The {puk_name} must have "
                                                     f"{BasicG1.PUK_LENGTH} letters or number "
                                                     f"characters")
        if not puk.isalnum():
            raise exceptions.DataValidationException(f"The {puk_name} must be letters and/or number"
                                                     f" characters.")

        return puk

    def verify_pin(self, pin: str) -> None:
        pin = self.valid_pin(pin)
        apdu = [0x80, 0x20, 0x00, 0x00]

        try:
            self.connection.send_encrypted(apdu, bytes(pin, 'ascii'))
        except exceptions.PinException as error:
            if error.number_of_retries != 0:
                raise

            apdu = [0x80, 0x22, 0x00, 0x00]
            try:
                self.connection.send_encrypted(apdu, bytes("", 'ascii') + bytes("", 'ascii'))
            except (exceptions.DataValidationException, exceptions.PinException):
                pass
            except exceptions.SecureChannelException as sc_error:
                raise exceptions.SoftLock("The card is soft locked. Power cycle required before it "
                                          "can be used again.") from sc_error
            raise
        except exceptions.GenericException as error:
            if error.status == 0x6700:
                raise exceptions.DataValidationException("Incorrect length")
            if error.status == 0x6986:
                raise exceptions.DataValidationException("PIN authentication disabled")

        if not self.open:
            self.auth_type = AuthType.PIN

    @staticmethod
    def _clear_bit(value, bit):
        return value & ~(1 << bit)

    @property
    def _info(self) -> bytes:
        try:
            result = self.connection.send_encrypted([0x80, 0xFA, 0x00, 0x00], b"")
        except exceptions.GenericException as error:
            if error.status[0] == 0x69 and error.status[1] == 0x85:
                raise exceptions.SecureChannelException("Command may need a secured channel")
            raise
        else:
            return result

    @property
    def _owner(self) -> base.User:
        try:
            data = self._info
        except exceptions.CryptnoxException:
            return base.User("", "")

        start = 1
        name_length = data[start]
        name = data[start + 1:start + name_length + 1].decode("ascii")
        email_length = data[name_length + 1 + start]
        user_list_offset = email_length + 2 + name_length + start
        email = data[start + name_length + 2:user_list_offset].decode("ascii")

        return base.User(name, email)

    @staticmethod
    def _set_bit(value, bit):
        return value | (1 << bit)
