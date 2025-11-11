cryptnox-sdk-py package
==================

Subpackages
-----------

.. toctree::
   :maxdepth: 4

   cryptnox-sdk-py.card
   cryptnox-sdk-py.cryptos

Submodules
----------

cryptnox-sdk-py.binary\_utils module
-------------------------------

.. automodule:: cryptnox-sdk-py.binary_utils
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox-sdk-py.connection module
----------------------------

.. automodule:: cryptnox-sdk-py.connection
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox-sdk-py.crypto\_utils module
-------------------------------

.. automodule:: cryptnox-sdk-py.crypto_utils
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox-sdk-py.enums module
-----------------------

.. automodule:: cryptnox-sdk-py.enums
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox-sdk-py.exceptions module
----------------------------

.. automodule:: cryptnox-sdk-py.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox-sdk-py.factory module
-------------------------

.. automodule:: cryptnox-sdk-py.factory
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox-sdk-py.reader module
------------------------

.. automodule:: cryptnox-sdk-py.reader
   :members:
   :undoc-members:
   :show-inheritance:

Module contents
---------------

.. automodule:: cryptnox-sdk-py
   :members:
   :undoc-members:
   :show-inheritance:

The ``cryptnox-sdk-py`` package is a library for communicating with Cryptnox cards. It exports:

.. py:currentmodule:: cryptnox-sdk-py

.. py:class:: Card
   :no-index:

   Main card interface class. Alias for :class:`cryptnox-sdk-py.card.base.Base`.

.. py:class:: Connection
   :no-index:

   Connection handler for card communication. See :class:`cryptnox-sdk-py.connection.Connection` for details.

.. py:module:: factory
   :no-index:

   Factory module for creating card instances. See :mod:`cryptnox-sdk-py.factory` for details.

.. py:module:: enums
   :no-index:

   Enumeration types module. See :mod:`cryptnox-sdk-py.enums` for details.

.. py:module:: exceptions
   :no-index:

   Exception classes module. See :mod:`cryptnox-sdk-py.exceptions` for details.

.. py:class:: SlotIndex
   :no-index:

   Card slot index enumeration. See :class:`cryptnox-sdk-py.enums.SlotIndex` for details.

.. py:class:: Derivation
   :no-index:

   Key derivation method enumeration. See :class:`cryptnox-sdk-py.enums.Derivation` for details.

.. py:class:: KeyType
   :no-index:

   Cryptographic key type enumeration. See :class:`cryptnox-sdk-py.enums.KeyType` for details.

.. py:class:: AuthType
   :no-index:

   Authentication type enumeration. See :class:`cryptnox-sdk-py.enums.AuthType` for details.

.. py:class:: SeedSource
   :no-index:

   Seed source enumeration. See :class:`cryptnox-sdk-py.enums.SeedSource` for details.

.. py:class:: Origin
   :no-index:

   Origin enumeration. See :class:`cryptnox-sdk-py.enums.Origin` for details.

.. py:data:: __version__
   :type: str
   :value: "2.5.6"

   Current version of the cryptnox-sdk-py library.