# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import sys
sys.path.insert(0, os.path.abspath(".."))

project = 'cryptnox_sdk_py'
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
    "sphinx.ext.graphviz",
    "sphinx.ext.inheritance_diagram",
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

# -- Graphviz configuration --------------------------------------------------
# Configuration for automatic class diagram generation

# Graphviz output format (svg provides high quality, scalable diagrams)
graphviz_output_format = 'svg'

# Global Graphviz options
graphviz_dot_args = [
    '-Gbgcolor=transparent',
    '-Nshape=box',
    '-Nstyle=rounded,filled',
    '-Nfillcolor=lightblue',
    '-Nfontname=Arial',
    '-Nfontsize=10',
    '-Efontsize=9',
]

# Inheritance diagram configuration
inheritance_graph_attrs = {
    'rankdir': 'TB',  # Top to Bottom layout
    'size': '"8.0, 12.0"',
    'bgcolor': 'transparent',
}

inheritance_node_attrs = {
    'shape': 'box',
    'style': '"rounded,filled"',
    'fillcolor': 'lightblue',
    'fontname': 'Arial',
    'fontsize': '10',
}

inheritance_edge_attrs = {
    'arrowsize': '0.8',
}

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ['_static']

# Logo configuration
html_logo = "_static/cryptnox-logo.png"

# Custom CSS and JS
html_css_files = [
    'custom.css',
]

html_js_files = [
    'custom.js',
]

# Theme options
html_theme_options = {
    'analytics_id': '',  # Provided by Google Analytics
    'logo_only': False,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': False,
    'vcs_pageview_mode': '',
    'style_nav_header_background': '#101f2e',
    # Toc options
    'collapse_navigation': True,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'includehidden': True,
    'titles_only': False
}
