=========
Changelog
=========

Version 1.0.3 - 2025-12-24
------------------------------------------------------------------------------------------------

Added
^^^^^^^

- Added ``get_manufacturer_certificate()`` method to Base card class with ``hexed`` parameter for flexible certificate retrieval

Changed
^^^^^^^

- Updated ``get_manufacturer_certificate()`` in BasicG1 with multi-page APDU support for full certificate retrieval
- Updated ``manufacturer_certificate()`` function in authenticity module to use the new card-specific method

Version 1.0.2 - 2025-12-08
------------------------------------------------------------------------------------------------

Changes
^^^^^^^

- Updated dependencies to resolve security vulnerabilities
- Improved Python 3 compatibility in cryptographic utilities

Added
^^^^^^^

- Implemented Python code quality scanning CI/CD pipeline using flake8
- Implemented security vulnerability scanning CI/CD pipeline using OSV-Scanner
- Added automated dependency security checks in GitHub Actions workflows

Fixed
^^^^^^^

- Fixed ``AttributeError: module 'cryptnox_sdk_py.cryptos.py2specials' has no attribute 'is_python2'`` error
- Fixed ``TypeError: can't concat str to bytes`` error in ``encode_pubkey()`` function
- Resolved info command issue that prevented retrieving card information
- Fixed Python 3.12 compatibility issues in ``py2specials.py`` module
  - Added proper Python 3 implementation for base 256 encoding/decoding
  - Fixed bytes/string handling in cryptographic operations

Version 1.0.1 - 2025-11-18
------------------------------------------------------------------------------------------------

Changes
^^^^^^^

- Package renamed from ``cryptnoxpy`` to ``cryptnox_sdk_py``
  - All imports must be updated from ``import cryptnoxpy`` to ``import cryptnox_sdk_py``
  - Install using: ``pip install cryptnox-sdk-py``
- Updated README.md with new package name and improved examples
- Updated valid PUK validation logic
- Updated GitHub Actions workflows for documentation and CI/CD
- Modified setup configuration (setup.cfg) for better package management

Added
^^^^^^^

- Added flake8 code quality checks to CI/CD workflow
- Added Sphinx documentation framework
- Implemented ``disconnect()`` method for Connection class to properly close connections
- Added comprehensive exception handling improvements

Fixed
^^^^^^^

- Fixed card not recognized error
- Resolved PUK retries persistence issue
- Fixed flake8 code style errors throughout the codebase

Removed
^^^^^^^

- Removed basic G0 cards references (no longer supported)
- Removed factory hashlib codes
