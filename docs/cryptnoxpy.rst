cryptnoxpy package
==================

Subpackages
-----------

.. toctree::
   :maxdepth: 4

   cryptnoxpy.card
   cryptnoxpy.cryptos

Submodules
----------

cryptnoxpy.binary\_utils module
-------------------------------

.. automodule:: cryptnoxpy.binary_utils
   :members:
   :undoc-members:
   :show-inheritance:

cryptnoxpy.connection module
----------------------------

.. automodule:: cryptnoxpy.connection
   :members:
   :undoc-members:
   :show-inheritance:

cryptnoxpy.crypto\_utils module
-------------------------------

.. automodule:: cryptnoxpy.crypto_utils
   :members:
   :undoc-members:
   :show-inheritance:

cryptnoxpy.enums module
-----------------------

.. automodule:: cryptnoxpy.enums
   :members:
   :undoc-members:
   :show-inheritance:

cryptnoxpy.exceptions module
----------------------------

.. automodule:: cryptnoxpy.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

cryptnoxpy.factory module
-------------------------

.. automodule:: cryptnoxpy.factory
   :members:
   :undoc-members:
   :show-inheritance:

cryptnoxpy.reader module
------------------------

.. automodule:: cryptnoxpy.reader
   :members:
   :undoc-members:
   :show-inheritance:

Module contents
---------------

.. automodule:: cryptnoxpy
   :members:
   :undoc-members:
   :show-inheritance:

The ``cryptnoxpy`` package is a library for communicating with Cryptnox cards. It exports:

.. py:currentmodule:: cryptnoxpy

.. py:class:: Card
   :no-index:

   Main card interface class. Alias for :class:`cryptnoxpy.card.base.Base`.

.. py:class:: Connection
   :no-index:

   Connection handler for card communication. See :class:`cryptnoxpy.connection.Connection` for details.

.. py:module:: factory
   :no-index:

   Factory module for creating card instances. See :mod:`cryptnoxpy.factory` for details.

.. py:module:: enums
   :no-index:

   Enumeration types module. See :mod:`cryptnoxpy.enums` for details.

.. py:module:: exceptions
   :no-index:

   Exception classes module. See :mod:`cryptnoxpy.exceptions` for details.

.. py:class:: SlotIndex
   :no-index:

   Card slot index enumeration. See :class:`cryptnoxpy.enums.SlotIndex` for details.

.. py:class:: Derivation
   :no-index:

   Key derivation method enumeration. See :class:`cryptnoxpy.enums.Derivation` for details.

.. py:class:: KeyType
   :no-index:

   Cryptographic key type enumeration. See :class:`cryptnoxpy.enums.KeyType` for details.

.. py:class:: AuthType
   :no-index:

   Authentication type enumeration. See :class:`cryptnoxpy.enums.AuthType` for details.

.. py:class:: SeedSource
   :no-index:

   Seed source enumeration. See :class:`cryptnoxpy.enums.SeedSource` for details.

.. py:class:: Origin
   :no-index:

   Origin enumeration. See :class:`cryptnoxpy.enums.Origin` for details.

.. py:data:: __version__
   :type: str
   :value: "2.5.5"

   Current version of the cryptnoxpy library.