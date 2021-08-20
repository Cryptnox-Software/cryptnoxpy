"""
Module containing common functionality for basic cards.
Don't use it by itself.
"""
import abc
import secrets
from typing import List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import base
from .. import exceptions
from ..binary_utils import binary_to_list, pad_data
from ..connection import Connection
from ..crypto_utils import aes_encrypt

_BASIC_PAIRING_SECRET = b'Cryptnox Basic CommonPairingData'


class Basic(base.Base, metaclass=abc.ABCMeta):
    """
    Class for basic cards containing common functionalities.
    """
    type = ord("B")
    pin_rule = "4-9 digits"

    def __init__(self, connection: Connection, data: List[int] = None, debug: bool = False):
        super(Basic, self).__init__(connection, data, debug)
        connection.pairing_secret = _BASIC_PAIRING_SECRET

    def change_pin(self, new_pin: str) -> None:
        new_pin = self.valid_pin(new_pin, pin_name="new pin")
        self._change_secret(0, new_pin)
        if not self.open:
            self.auth_type = base.AuthType.PIN

    def change_puk(self, current_puk: str, new_puk: str) -> None:
        current_puk = self.valid_puk(current_puk, "current puk")
        new_puk = self.valid_puk(new_puk, "new puk")
        try:
            self._change_secret(1, new_puk + current_puk)
        except exceptions.DataValidationException as error:
            raise exceptions.DataValidationException("The current puk is not matching "
                                                     "the one on the card") from error
        if not self.open:
            self.auth_type = base.AuthType.PIN

    def init(self, name: str, email: str, pin: str, puk: str,
             pairing_secret: bytes = _BASIC_PAIRING_SECRET) -> bytes:
        puk = self.valid_puk(puk)
        pin = self.valid_pin(pin)
        if len(name) > 20:
            raise exceptions.DataValidationException("Name must be less than 20 characters")
        if len(email) > 60:
            raise exceptions.DataValidationException("Name must be less than 60 characters")
        pairing_secret = pairing_secret or _BASIC_PAIRING_SECRET

        session_private_key = ec.generate_private_key(self._ALGORITHM)

        session_public_key = session_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint)

        send_public_key = bytes.fromhex("{:x}".format(len(session_public_key)) +
                                        session_public_key.hex())

        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self._ALGORITHM(), bytes.fromhex(self.connection.session_public_key))
        aes_init_key = session_private_key.exchange(ec.ECDH(), public_key)

        iv_init_key = secrets.token_bytes(nbytes=16)

        data = self._get_coded_value(name) + self._get_coded_value(email) + bytes(pin, 'ascii')
        data += bytes(puk, 'ascii') + pairing_secret

        payload = pad_data(data)
        encrypted_payload = aes_encrypt(aes_init_key, iv_init_key, payload)
        data_init = send_public_key + iv_init_key + encrypted_payload
        apdu_init = [0x80, 0xFE, 0x00, 0x00, 82 + len(encrypted_payload)]
        apdu_init += binary_to_list(data_init)
        _, code1, code2 = self.connection.send_apdu(apdu_init)

        if code1 != 0x90 or code2 != 0x00:
            raise exceptions.InitializationException("Card is not initialized")

        return bytes([0]) + pairing_secret

    def unblock_pin(self, puk: str, new_pin: str) -> None:
        apdu = [0x80, 0x22, 0x00, 0x00]
        puk = self.valid_puk(puk)
        new_pin = self.valid_pin(new_pin, pin_name="new pin")
        try:
            self.connection.send_encrypted(
                apdu, bytes(puk, 'ascii') + bytes(new_pin, 'ascii'))
        except exceptions.PinException as error:
            raise exceptions.PukException(error.number_of_retries,
                                          "Invalid puk is provided") from error
        except exceptions.SecureChannelException as error:
            raise exceptions.CardNotBlocked("Card is not blocked") from error

        if not self.open:
            self.auth_type = base.AuthType.PIN

    @staticmethod
    def valid_pin(pin: str, pin_name: str = "pin") -> str:
        if not 4 <= len(pin) <= 9:
            raise exceptions.DataValidationException(f"The {pin_name} must have between"
                                                     f" 4 and 9 numeric characters")

        if not pin.isdigit():
            raise exceptions.DataValidationException(f"The {pin_name} must be numeric.")

        return pin + ("\0" * (9 - len(pin)))

    def _change_secret(self, select_pin_puk: int, value: str):
        """
        Change secret, PIN or PUK code, of the card

        :param int select_pin_puk: Change the PIN or PUK code:
                                   0 - PIN
                                   1 - PUK
        :param str value: Value of the new secret
        """
        message = [0x80, 0x21, select_pin_puk, 0x00]

        self.connection.send_encrypted(message, bytes(value, 'ascii'))

    @staticmethod
    def _get_coded_value(value):
        value_bytes = bytes(value, 'ascii')
        return bytes([len(value_bytes)]) + value_bytes
