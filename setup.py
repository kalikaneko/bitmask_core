# -*- coding: utf-8 -*-
# setup.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
setup file for leap.bitmask_core
"""
import re
from setuptools import setup, find_packages

from pkg import utils

import versioneer

parsed_reqs = utils.parse_requirements()


trove_classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    ("License :: OSI Approved :: GNU General "
     "Public License v3 or later (GPLv3+)"),
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 2.7",
    "Topic :: Communications",
    "Topic :: Security",
    "Topic :: Utilities"
]

DOWNLOAD_BASE = ('https://github.com/leapcode/bitmask_core/'
                 'archive/%s.tar.gz')

VERSION = versioneer.get_version()
DOWNLOAD_URL = ""

# get the short version for the download url
#_version_short = re.findall('\d+\.\d+\.\d+', VERSION)
#if len(_version_short) > 0:
    #VERSION_SHORT = _version_short[0]
    #DOWNLOAD_URL = DOWNLOAD_BASE % VERSION_SHORT

cmdclass = versioneer.get_cmdclass()

try:
    long_description = open('README.rst').read() + '\n\n\n' + \
        open('CHANGELOG').read()
except Exception:
    long_description = ""

bitmask_cli = 'bitmask_cli=leap.bitmask_core.bitmask_cli:main'
bitmaskd = 'bitmaskd=leap.bitmask_core.launcher:run_bitmaskd'

setup(
    name='leap.bitmask_core',
    version=VERSION,
    cmdclass=cmdclass,
    url='https://leap.se/',
    #download_url=DOWNLOAD_URL,
    license='GPLv3+',
    author='The LEAP Encryption Access Project',
    author_email='info@leap.se',
    maintainer='Kali Kaneko',
    maintainer_email='kali@leap.se',
    description='Common files used by the LEAP project.',
    long_description=long_description,
    classifiers=trove_classifiers,
    namespace_packages=["leap"],
    package_dir={'': 'src'},
    package_data={'': ['*.pem']},
    packages=find_packages('src'),
    test_suite='leap.bitmask_core.tests',
    install_requires=parsed_reqs,
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [bitmask_cli, bitmaskd]
    },
)
