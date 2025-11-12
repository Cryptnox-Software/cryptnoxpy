"""
Configuration for setting up Cryptnox SDK Python as external library
"""
import pathlib
import sys

from setuptools import setup


def read(file):
    return (pathlib.Path(__file__).parent / file).read_text("utf-8").strip()


PYSCARD = "pyscard"
if sys.platform.startswith("win"):
    PYSCARD += "==2.2.0"

setup(
    install_requires=[
        "aiohttp",
        "cryptography",
        PYSCARD
    ],
    long_description="\n\n".join((read("README.md"), read("CHANGELOG.rst"))),
    long_description_content_type="text/markdown",
)
