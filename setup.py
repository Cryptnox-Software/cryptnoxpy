"""
Configuration for setting up CryptnoxPy as external library
"""
import os
import sys

from setuptools import setup

PYSCARD = "pyscard"

dependencies = [
    "aiohttp",
    "cryptography",
    "pbr",
]

print('os.environ.get("build")', os.environ.get("build"))

if os.environ.get("build") == "readthedocs":
    dependencies += [
        "autoapi",
        "sphinx",
        "sphinx-autoapi"
    ]
else:
    if sys.platform.startswith("win"):
        PYSCARD += "==2.0.1"

    dependencies += [
        PYSCARD
    ]

setup(pbr=True,
      setup_requires=['pbr'],
      platforms=['any'],
      python_requires=">=3.6,<3.10",
      install_requires=dependencies,
      )
