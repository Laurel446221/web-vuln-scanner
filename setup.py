from setuptools import setup, find_packages
import os

# Read the contents of README.md
try:
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    long_description = "Advanced web vulnerability scanner for penetration testers"

# Read requirements.txt if it exists
requirements = []
try:
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        requirements = fh.read().splitlines()
        # Remove empty lines and comments
        requirements = [req.strip() for req in requirements if req.strip() and not req.startswith('#')]
except FileNotFoundError:
    # Default requirements if requirements.txt doesn't exist
    requirements = [
        "requests>=2.25.1",
        "beautifulsoup4>=4.9.3",
        "urllib3>=1.26.5"
    ]

setup(
    name="webvulnscanner",
    version="2.0.0",
    author="Laurel Megida",
    author_email="laurelmegida@gmail.com",
    description="Advanced web vulnerability scanner for penetration testers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/laurelmegida/webvulnscanner",  # Update with your actual repo URL
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "webvulnscanner=cli:main",
        ],
    },
    python_requires=">=3.7",
    keywords="security, pentesting, vulnerability-scanner, web-security, cybersecurity",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    license="MIT",  # Choose appropriate license
)