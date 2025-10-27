# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import sys
sys.path.insert(0, os.path.abspath(".."))

project = 'cryptnoxpy'
copyright = '2025, Cryptnox'
author = 'Cryptnox'
release = '1.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

# Disable autosummary generation to prevent hangs
autosummary_generate = False

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# Mock external dependencies to prevent import errors during doc build
autodoc_mock_imports = [
    'pyscard',
    'smartcard',
    'smartcard.System',
    'smartcard.CardConnection',
    'smartcard.Exceptions',
    'smartcard.CardType',
    'smartcard.CardRequest',
    'smartcard.util',
    'smartcard.scard',
    'cryptography',
    'cffi',
    'aiohttp',
    'aiosignal',
    'attrs',
]

# Autodoc configuration
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'exclude-members': '__weakref__'
}

# Handle ambiguous cross-references
nitpicky = False
nitpick_ignore = [
    ('py:class', 'Base'),
    ('py:class', 'ConnectionException'),
    ('py:class', 'CardException'),
]

# Suppress specific warnings
suppress_warnings = [
    'ref.python',
    'toc.not_included',
]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ['_static']
