=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_\ ,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

`Unreleased <https://github.com/Cryptnox-Software/cryptnoxpy/compare/v1.1.0...HEAD>`_
-------------------------------------------------------------------------------------

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
