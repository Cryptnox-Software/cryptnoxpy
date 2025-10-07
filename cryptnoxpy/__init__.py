# -*- coding: utf-8 -*-
"""
This is a library for communicating with Cryptnox cards

See the README.md for API details and general information.
"""
from .card.base import Base as Card
from .connection import Connection
from . import factory
from .enums import *  # noqa: F401,F403
from .exceptions import *  # noqa: F401,F403

__version__ = "2.5.5"

# Make imports available for external use
# Note: Star imports from enums and exceptions are intentionally used
# to make all enums and exceptions available at package level
__all__ = [
    'Card',
    'Connection',
    'factory',
    '__version__'
]
