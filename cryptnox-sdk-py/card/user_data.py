# -*- coding: utf-8 -*-
"""
Module for making the uer data behave as a list
"""
from .. import exceptions

_PAGE_SIZE = 1200


class UserDataBase:
    """
    Class for User Data with all functions returning not implemented in case someone uses it on a
    card that doesn't support the feature
    """

    def __getitem__(self, item):
        raise NotImplementedError("Card doesn't have this functionality")

    def __setitem__(self, key, value):
        raise NotImplementedError("Card doesn't have this functionality")


class UserData:
    """
    User data that behaves as a list and can fetch different user slots from the card
    """

    def __init__(self, card, slot_offset: int = 0, reading_index_offset: int = 0):
        self.card = card
        self._slot_offset = slot_offset
        self._reading_index_offset = reading_index_offset

    def __getitem__(self, slot: int = 0):
        result = b""
        index = 0
        while True:
            message = [0x80, 0xFA, slot + self._slot_offset, index + self._reading_index_offset]
            try:
                result += self.card.connection.send_encrypted(message, b"", True)
            except exceptions.GenericException as error:
                if (error.status[0] == 0x6B and error.status[1] == 0x00) or \
                        (error.status[0] == 0x6A and error.status[1] == 0x86):
                    break
                if error.status[0] == 0x69 and error.status[1] == 0x85:
                    raise exceptions.SecureChannelException("Command may need a secured channel")
                raise
            index += 1

        return result

    def __setitem__(self, slot, value):
        value_to_send = [value[i:i + _PAGE_SIZE] for i in range(0, len(value), _PAGE_SIZE)]

        for index, entry in enumerate(value_to_send):
            message = [0x80, 0xFC, slot + self._slot_offset, index]
            try:
                self.card.connection.send_encrypted(message, entry)
            except exceptions.GenericException as error:
                if error.status[0] == 0x69 and error.status[1] == 0x85:
                    raise exceptions.CardClosedException("Card needs to be opened for this operation")
                if error.status[0] == 0x67 and error.status[1] == 0x00:
                    raise exceptions.DataValidationException("Value to large to write")

                raise
            index += 1
