from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from pyexpat.errors import messages

import cryptnoxpy
from cryptnoxpy import SlotIndex, KeyType
from cryptnoxpy.enums import Derivation

try:
    connection = cryptnoxpy.Connection(0)
except cryptnoxpy.ReaderException:
    print("Reader not found on index")
else:
    try:
        card = cryptnoxpy.factory.get_card(connection)
    except cryptnoxpy.CryptnoxException as error:
        # There is an issue with loading the card
        # CryptnoxException is the base exception class for module
        print(error)
    else:
        # Card is loaded and can be used
        print(f"Card serial number: {card.serial_number}")
        print(f"applet_version: {card.applet_version}")
        print(f"type: {card.type}")
        print(f"initialized: {card.initialized}")
        print(f"alive: {card.alive}")
        print(f"seed_source: {card.seed_source}")
        print(f"auth_type: {card.auth_type}")
        print(f"check_init: {card.check_init()}")
        print(f"info: {card.info}")

        # card.reset('000000000000')

        # card.init('naytoe', 'naytoe@mail.com', '000000000', '000000000000')
        # print(f"check_init: {card.check_init()}")

        # card.verify_pin('000000000')
        # card.change_pin('000000000')
        # card.change_puk('000000000000', "000000000001")

        # BASIC_PAIRING_SECRET2 = b'Cryptnox Basic CommonPairingDato'
        # card.change_pairing_key(0, BASIC_PAIRING_SECRET2, '000000000000')

        # card.generate_seed('000000000')

        # public_key = card.get_public_key(Derivation.CURRENT_KEY)
        # print(f"public_key: {public_key}")

        # print(f"session_public_key: {card.connection.session_public_key}")

        # number = card.generate_random_number(16)
        # print(f"number {number}")

        # private_key_hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        #
        # private_key_bytes = bytes.fromhex(private_key_hex[2:])
        # private_key = ec.derive_private_key(int(private_key_hex, 16), ec.SECP256R1(), default_backend())
        #
        # public_key = private_key.public_key()
        # user_public_key = public_key.public_bytes(
        #     serialization.Encoding.X962,
        #     serialization.PublicFormat.UncompressedPoint)
        #
        # print(f"public {user_public_key.hex()}")

        # print(f"user_key_enabled {card.user_key_enabled(SlotIndex.EC256R1)}")

        # card.user_key_delete(SlotIndex.EC256R1, '000000000000')

        # card.user_key_add(SlotIndex.EC256R1,'some data', user_public_key, '000000000000')

        # nonce = card.user_key_challenge_response_nonce()
        # challenge_response_open = card.user_key_challenge_response_open(SlotIndex.EC256R1, private_key.sign(nonce, ec.ECDSA(hashes.SHA256())))
        #
        # print(f"challenge_response_open {challenge_response_open}")
        #
        # message = b'thirtytwo_byte_message_to_signed'
        # messageSig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        #
        # signature_open = card.user_key_signature_open(SlotIndex.EC256R1, message, messageSig)
        #
        # print(f"signature_open {signature_open}")
        #
        # sign = card.sign(message, Derivation.CURRENT_KEY)
        #
        # print(f"sign {sign.hex()}")
        #
        # try:
        #     public_key.verify(
        #         messageSig,  # The DER-encoded signature
        #         message,  # The original data that was signed
        #         ec.ECDSA(hashes.SHA256())  # The signature algorithm and hash function
        #     )
        #     print("Signature is valid.")
        # except InvalidSignature:
        #     print("Signature is invalid.")

        print(f"---------------Done---------------")