# -*- coding: utf-8 -*-
"""
Module for making the uer data behave as a list
"""


class CustomBitsBase:
    """
    Class for User Data with all functions returning not implemented in case someone uses it on a
    card that doesn't support the feature
    """

    def __getitem__(self, item):
        raise NotImplementedError("Card doesn't have this functionality")

    def __setitem__(self, key, value):
        raise NotImplementedError("Card doesn't have this functionality")


class CustomBits:
    def __init__(self, data, set_item_callback):
        self._data = data
        self._set_item_callback = set_item_callback

    def __getitem__(self, position):
        if 0 > position > len(self._data) * 8:
            raise IndexError('Position out of bounds')

        list_position = position // 8
        element_position = position % list_position if list_position else position
        list_position = len(self._data) - list_position - 1

        return (self._data[list_position] >> element_position) & 1

    def __setitem__(self, position, value):
        if 0 > position > len(self._data) * 8:
            raise IndexError('Position out of bounds')

        list_position = position // 8
        element_position = len(self._data) % list_position if list_position else position
        list_position = len(self._data) - list_position - 1

        if value:
            self._data[list_position] = self._data[list_position] | (1 << element_position)
        else:
            self._data[list_position] = self._data[list_position] & ~(1 << element_position)

        try:
            self._set_item_callback(bytes(self._data))
        except TypeError:
            pass
