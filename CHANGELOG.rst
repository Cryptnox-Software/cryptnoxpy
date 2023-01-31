=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_\ ,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

`Unreleased <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.3.0...HEAD>`_
-------------------------------------------------------------------------------------

`2.4.0 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.3.0...2.4.0>`_ - 2023-01-31
-----------------------------------------------------------------------------------------------

Changed
^^^^^^^

- Remote connection message format, not compatible with previous version

`2.3.0 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.2.1...2.3.0>`_ - 2022-11-28
-----------------------------------------------------------------------------------------------

Added
^^^^^

- Ability to write and read custom bytes from select command

`2.2.1 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.2.0...2.2.1>`_ - 2022-07-14
-----------------------------------------------------------------------------------------------

Fixed
^^^^^

- Installation for Python 3.10

`2.2.0 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.1.1...2.2.0>`_ - 2022-07-13
-----------------------------------------------------------------------------------------------

Added
^^^^^

- Support for Python 3.10

Removed
^^^^^^^

- Support for Python 3.6

Fixed
^^^^^

- `get_public_key` raises an unhandled exception when asking for current key with a derivation path

`2.1.1 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.1.0...2.1.1>`_ - 2022-06-13
-----------------------------------------------------------------------------------------------

Added
^^^^^

- Add optional "hexed" parameter in get_public_key of cards

`2.1.0 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.0.3...v2.1.0>`_ - 2022-06-01
-----------------------------------------------------------------------------------------------

Added
^^^^^

- Add option for cards from remote connection

`2.0.3 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.0.2...v2.0.3>`_ - 2022-03-14
-----------------------------------------------------------------------------------------------

Changed
^^^^^^^

- Installation instructions added missing instructions

Fixed
^^^^^

- `generate_seed` command allowed without previously verifying PIN code


`2.0.2 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.0.1...v2.0.2>`_ - 2022-03-14
-----------------------------------------------------------------------------------------------

Fixed
^^^^^

- `unblock_pin` command shows "PIN code wasn't authorized" when card is not locked

`2.0.1 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v2.0.0...v2.0.1>`_ - 2022-01-03
-----------------------------------------------------------------------------------------------

Fixed
^^^^^

- Printing debug data during requests call for certificates

`2.0.0 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.1.6...v2.0.0>`_ - 2022-01-03
-----------------------------------------------------------------------------------------------

Added
^^^^^

- New cad type, NFT, with limited functionality intended for keeping one NFT
- Method for checking private key validity

Changed
^^^^^^^

- User data read and write property to list
- pyscard on windows fixed to version 2.0.1, in pipenv all OSes.

`1.1.6 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.1.5...v1.1.6>`_ - 2021-11-03
-----------------------------------------------------------------------------------------------

Fixed
^^^^^

* Debug parameter not passed when creating card class

`1.1.5 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.1.4...v1.1.5>`_ - 2021-10-29
-----------------------------------------------------------------------------------------------

Fixed
^^^^^

* Genuineness check made more resilient to exceptions

`1.1.4 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.1.3...v1.1.4>`_ - 2021-10-21
-----------------------------------------------------------------------------------------------

Fixed
^^^^^

* Opening secure channel with G0 card throws exception

`1.1.3 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.1.2...v1.1.3>`_ - 2021-10-20
-----------------------------------------------------------------------------------------------

Fixed
^^^^^

* sign operation throws error if PIN code is not provided when user key is used for authentication.

`1.1.2 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.1.1...v1.1.2>`_ - 2021-10-07
-----------------------------------------------------------------------------------------------

Fixed
^^^^^

* Handling of error response from the card for not authenticated

`1.1.1 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.1.0...v1.1.1>`_ - 2021-10-06
-----------------------------------------------------------------------------------------------

Changed
^^^^^^^

* User data size increased to 3600 bytes

Fixed
^^^^^

* Set PIN-less path didn't convert input path to correct values for card
* Setting PIN-less path and PIN authentication doesn't set flags for indication
* Sign method doesn't fill up given PIN code with 0s up to 9 characters

`1.1.0 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.0.4...v1.1.0>`_ - 2021-09-24
-----------------------------------------------------------------------------------------------

Added
^^^^^

* Origin property for indicating if the card is original or not or check can't be done.

Changed
^^^^^^^

* PyScard updated to 2.0.2

Fixed
^^^^^

* When card is not initialized seed_source property throws exception. Return `SeedSource.NO_SEED` instead
* When seed is generated in the card the flag for it stays the same
* Operation unlock_pin doesn't raise exception when card is not locked

`1.0.4 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.0.3...v1.0.4>`_ - 2021-09-09
-----------------------------------------------------------------------------------------------

Changed
^^^^^^^

* Improvements in setup

`1.0.3 <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.0.0...v1.0.3>`_ - 2021-09-07
-----------------------------------------------------------------------------------------------

Changed
^^^^^^^

* Documentation changed to rst
* Version number stored in the module instead of getting it from pbr

Removed
^^^^^^^

* PBR dependency

Fixed
^^^^^

* PyPI doesn't install dependencies

`1.0.0 <https://github.com/Cryptnox-Software/cryptnoxpy/releases/tag/v1.0.0>`_ - 2021-08-20
-------------------------------------------------------------------------------------------

Added
^^^^^

* Card operations
* Pipfile and requirements for setting up environment
* Setup file to install the library
