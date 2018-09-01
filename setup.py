#!/usr/bin/env python3

import setuptools

setuptools.setup(
    name="bgpkit",
    version="1.0",
    packages=[
            "bgpkit"
    ],
    author="Fritz Grimpen",
    author_email="fritz@grimpen.net",
    url="https://github.com/fritz0705/bgpkit",
    license="http://opensource.org/licenses/MIT",
    description="Lightweight BGP toolkit",
    classifiers=[
            "Development Status :: 4 - Beta",
            "Operating System :: POSIX",
            "Programming Language :: Python :: 3 :: Only",
            "Programming Language :: Python :: 3.7",
            "Topic :: System :: Networking"
    ],
    install_requires=[
        "netaddr"
    ],
    package_data={
    }
)
