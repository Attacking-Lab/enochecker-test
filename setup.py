#!/usr/bin/env python3
import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="enochecker_test",
    version="0.4.0",
    author="ldruschk",
    author_email="ldruschk@posteo.de",
    description="Library to help testing checker scripts based on enochecker",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/enowars/enochecker_test",
    packages=setuptools.find_packages(),
    entry_points = {
        "console_scripts": ['enochecker_test = enochecker_test.main:main']
    },
    install_requires=requirements,
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 3 - Alpha",
        # Indicate who your project is intended for
        # 'Intended Audience :: Developers',
        "License :: OSI Approved :: MIT License",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    zip_safe=False,  # This might be needed for reqirements.txt
    python_requires=">=3.7",
)
