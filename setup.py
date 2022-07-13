"""
Configuration for setting up CryptnoxPy as external library
"""
import pathlib
import sys

from setuptools import setup


def read(file):
    return (pathlib.Path(__file__).parent / file).read_text("utf-8").strip()


PYSCARD = "pyscard"
if sys.platform.startswith("win"):
    PYSCARD += "==2.0.3"

setup(
    install_requires=[
        "aiohttp",
        "cryptography",
        PYSCARD
    ],
    long_description="\n\n".join((read("README.rst"), read("CHANGELOG.rst"))),
)
