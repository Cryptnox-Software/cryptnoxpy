=========
Changelog
=========

`1.0.1 <https://github.com/Cryptnox-Software/cryptnox_sdk_py/compare/v2.5.5...v1.0.1>`_ - 2025-11-18
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

`2.5.5 <https://github.com/Cryptnox-Software/cryptnox-sdk-py/releases/tag/v2.5.5>`_ - 2025-09-29
------------------------------------------------------------------------------------------------

Changed
^^^^^^^

- Handled get public key clear with different public key formats

Fixed
^^^^^^^

- Resolved card detection by implementing x509 parsing
