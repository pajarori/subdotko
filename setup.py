from setuptools import setup, find_packages

setup(
    name="subdotko",
    version="1.4.2",
    description="Subdomain Takeover Scanner - Fingerprint-based subdomain takeover detection tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="pajarori",
    url="https://github.com/pajarori/subdotko",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "dnspython",
        "httpx",
        "pyyaml",
        "rich",
        "tldextract",
    ],
    entry_points={
        "console_scripts": [
            "subdotko=subdotko.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
