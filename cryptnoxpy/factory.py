"""
Module for getting Cryptnox cards information and getting instance of card from
connection
"""
from typing import Tuple, Any, Dict

from .card import (
    genuineness,
    Base
)
from .card import BasicG0 # pylint: disable=unused-import
from .card import BasicG1 # pylint: disable=unused-import

from .connection import Connection
from .exceptions import (
    CardException,
    CardTypeException,
    CertificateException,
    DataException,
    FirmwareException
)


def get_card(connection: Connection, debug: bool = False) -> Base:
    """
    Get card instance that is using given connection.

    :param Connection connection: Connection to use for operation
    :param bool debug: Prints information about communication

    :return: Instance of card
    :rtype: Base

    :raise CardException: Card with given serial number not found
    """
    for card_cls in _all_subclasses(Base):
        try:
            applet_version, data = _select(connection, card_cls.select_apdu, card_cls.type)
            serial, _ = _serial_number(connection, debug)
        except (TypeError, CardTypeException, CertificateException, DataException,
                FirmwareException):
            continue

        connection.session_public_key = genuineness.session_public_key(connection, debug)

        return card_cls(connection, serial, applet_version, data)

    raise CardException("Card not recognized")


def _all_subclasses(cls):
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in _all_subclasses(c)])


def _select(connection, apdu, card_type, debug: bool = False) -> Tuple[Any, Any]:
    apdu = [0x00, 0xA4, 0x04, 0x00, 0x07] + apdu

    data_selected = connection.send_apdu(apdu)[0]
    if len(data_selected) == 0:
        raise DataException("This card is not answering any data. Are you "
                            "using NFC?")

    if card_type != data_selected[0]:
        raise CardTypeException("Type not recognized")

    applet_version = data_selected[1:4]
    data = data_selected[4:36]

    if debug:
        print("Applet Version")
        print(applet_version)

    return applet_version, data


def _serial_number(connection: Connection, debug: bool = False):
    certificate = genuineness.manufacturer_certificate(connection, debug)
    certificate_parts = certificate.split("0302010202")
    if len(certificate_parts) <= 1:
        raise CertificateException("No card certificate found")

    try:
        if certificate_parts[1][1] == "8":
            data = certificate_parts[1][2:18]
        elif certificate_parts[1][1] == "9":
            data = certificate_parts[1][4:20]
        else:
            raise CertificateException("Bad certificate format")

    except Exception as error:
        raise CertificateException("Bad card certificate format") from error

    return int(data, 16), certificate
