#!/usr/bin/env python3
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Written by:
#        Nadzeya Hutsko <nadzya.info@gmail.com>

import codecs
import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

INSTALL_REQUIRES = ["pylintfileheader", "scapy"]

setup(
    name="hackme",
    version="0.3.0",
    py_modules=["hackmeapp"],
    description="Scripts that implement different network attacks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["hackme"],
    zip_safe=False,
    install_requires=INSTALL_REQUIRES,
    # test_suite="",
    entry_points="""
        [console_scripts]
        hackme=hackmeapp:main
    """,
)
