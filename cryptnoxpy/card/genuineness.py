"""
Module containing check for verification of genuineness of a card
"""
import asyncio
import re
import secrets
import sys
from typing import List

import aiohttp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..binary_utils import list_to_hexadecimal, hexadecimal_to_list
from ..connection import Connection
from ..exceptions import GenuineCheckException

_ECDSA_SHA256 = "06082a8648ce3d040302" + "03"
_MANUFACTURER_CERTIFICATE_URL = "https://verify.cryptnox.tech/certificates/"
_PUBLIC_K1_OID = "2a8648ce3d030107034200"


def check(connection: Connection, debug: bool = False) -> str:
    """
    Check if the card in the reader is genuine Cryptnox product

    :param Connection connection: Connection to use for operation
    :param bool debug: Prints information about communication

    :return: Session public key to use opening secure channel
    :rtype: str

    :raise GenuineCheckException: The card is not genuine
    """
    _check_manufacturer_certificate(connection, debug)

    card_cert_hex = _get_card_certificate(connection, debug)
    session_public_key = card_cert_hex[18:148]
    card_cert_msg = bytes.fromhex(card_cert_hex[:148])
    card_cert_sig_hex = card_cert_hex[148:]

    if debug:
        print("Card msg")
        print(card_cert_msg.hex())
        print("Card sig")
        print(card_cert_sig_hex)

    public_key = bytes.fromhex(_public_key(connection))
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
    if not _check_signature(card_cert_msg, public_key, card_cert_sig_hex):
        raise GenuineCheckException("Wrong card signature")

    return session_public_key


def manufacturer_certificate(connection: Connection, debug: bool = False) -> str:
    """
    Get the manufacturer certificate from the card in connection.

    :param Connection connection: Connection to use for operation
    :param bool debug: Prints information about communication

    :return: Manufacturer certificate read from the card
    :rtype: str
    """
    apdu = [0x80, 0xF7, 0x00, 0x00, 0x00]
    response = connection.send_apdu(apdu)[0]

    if not response:
        return ""

    apdu = [0x80, 0xF7, 0x00, 0x01, 0x00]
    response = response + connection.send_apdu(apdu)[0]
    length = (response[0] << 8) + response[1]
    assert len(response) == (length + 2)
    certificate = list_to_hexadecimal(response[2:])
    if debug:
        print(f"Manufacturer certificate: {certificate}")

    return certificate


def _manufacturer_public_keys():
    async def fetch(session, url):
        async with session.get(url) as response:
            certificate = await response.text()
            return x509.load_pem_x509_certificate(certificate.encode("ascii")).public_key()

    async def fetch_all(session, certificates):
        tasks = [asyncio.create_task(fetch(session, _MANUFACTURER_CERTIFICATE_URL + certificate))
                 for certificate in certificates]

        results = await asyncio.gather(*tasks)

        return results

    async def fetch_certificates():
        async with aiohttp.ClientSession() as session:
            async with session.get(_MANUFACTURER_CERTIFICATE_URL) as response:
                data = await response.text()
                certificates = re.findall('href="(.+?crt)"', data)

        async with aiohttp.ClientSession() as session:
            return await fetch_all(session, certificates)

    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    return asyncio.run(fetch_certificates())

def _check_manufacturer_certificate(connection: Connection, debug: bool = False) -> None:
    manufacturer_certificate_data = _manufacturer_certificate_data(connection, debug)
    signature = _manufacturer_signature(connection, debug)

    certified = False
    for public_key in _manufacturer_public_keys():
        certified |= _check_signature(manufacturer_certificate_data, public_key, signature)

        if certified:
            break

    if not certified:
        raise GenuineCheckException("Wrong Cryptnox factory signature")


def _check_signature(message: bytes, public_key: ec.EllipticCurvePublicKey, signature_hex: str) -> bool:
    try:
        public_key.verify(bytes.fromhex(signature_hex), message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False

    return True


def _certificate_parts(connection: Connection, debug: bool = False) -> List[str]:
    # car pub hex 65B after r1:2a8648ce3d030107034200 k1:2b8104000a034200
    parts = manufacturer_certificate(connection, debug).split(_PUBLIC_K1_OID)
    if len(parts) < 2:
        raise GenuineCheckException("No ECDSA r1 Public key found")

    return parts


def _public_key(connection: Connection, debug: bool = False) -> str:
    public_key = _certificate_parts(connection)[1][:130]

    if debug:
        print("card public key hex")
        print(public_key)

    return public_key


def _manufacturer_certificate_data(connection: Connection, debug: bool = False) -> bytes:
    # datacert_hex : prem partie + 2a8648ce3d030107034200 + pubhex
    result = bytes.fromhex(_certificate_parts(connection, debug)[0][8:] +
                           _PUBLIC_K1_OID + _public_key(connection))
    if debug:
        print("Manufacturer data")
        print(result.hex())

    return result


def _get_card_certificate(connection: Connection, debug: bool = False) -> str:
    nonce = secrets.randbits(64)
    nonce_list = hexadecimal_to_list("%0.16X" % nonce)
    certificate = connection.send_apdu([0x80, 0xF8, 0x00, 0x00] +
                                       [8] + nonce_list)[0]

    card_cert_hex = list_to_hexadecimal(certificate)
    if debug:
        print("Card cert")
        print(card_cert_hex)
    # C ?
    if card_cert_hex[:2] != "43":
        print("Bad card certificate header")
        return ""
    # Nonce?
    if int(card_cert_hex[2:18], 16) != nonce:
        print("Card certificate nonce is not the one provided")
        return ""

    return card_cert_hex


def _manufacturer_signature(connection: Connection, debug: bool = False) -> str:
    certificate_parts = manufacturer_certificate(connection,
                                                 debug).split(_ECDSA_SHA256)

    if len(certificate_parts) < 2:
        return ""

    signature_length = int(certificate_parts[1][0:2], 16)
    signature = certificate_parts[1][2:]

    assert len(signature) == 2 * signature_length

    if certificate_parts[1][2:4] == "00":
        signature = certificate_parts[1][4:]

    if debug:
        print("mft cert sig hex")
        print(signature)

    return signature
