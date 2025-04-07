from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="quantum-encryptor",
    version="1.0.0",
    author="brainx",
    author_email="brainx@posteo.de",
    description="Post-quantum cryptography tool for file encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/brainx/quantum-encryptor",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=[
        "liboqs>=0.7.2",
        "pyoqs>=0.4.0",
        "cryptography>=39.0.0",
        "streamlit>=1.22.0",
    ],
) 