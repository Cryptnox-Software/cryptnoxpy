"""
Configuration for setting up CryptnoxPy as external library
"""
import sys

from setuptools import setup

PYSCARD = "pyscard"
if sys.platform.startswith("win"):
    PYSCARD += "==2.0.1"

dependencies = [
    "aiohttp",
    "cryptography",
    "pbr",
    PYSCARD
]

setup(pbr=True,
      setup_requires=['pbr'],
      platforms=['any'],
      python_requires=">=3.6,<3.10",
      install_requires=dependencies,
      )
