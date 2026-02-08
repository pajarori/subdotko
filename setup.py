from setuptools import setup, find_packages

setup(
    name="subdotko",
    version="1.0.3",
    description="Subdomain Takeover Scanner - Fingerprint-based subdomain takeover detection tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Pajarori",
    url="https://github.com/pajarori/subdotko",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "dnspython",
        "requests",
        "pyyaml",
        "rich",
        "urllib3",
        "tldextract",
    ],
    entry_points={
        "console_scripts": [
            "subdotko=subdotko.subdotko:main",
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
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
