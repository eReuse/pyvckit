from setuptools import setup, find_packages

test_requires = [
        'requests_mock'
        "pytest",
        "pyroaring",
        "didkit"
]

setup(
    name="pyvckit",
    version="0.0.12",
    packages=['pyvckit'],
    install_requires=[
        "jsonref",
        "PyLD",
        "Requests",
        "jsonschema[format]",
        "jsonref",
        "asn1crypto",
        "certifi",
        "cffi",
        "cryptography",
        "fonttools",
        "idna",
        "jsonwebtoken",
        "jwcrypto",
        "oscrypto",
        "pycparser",
        "pyedid",
        "pyHanko[opentype]",
        "pyhanko-certvalidator",
        "pyOpenSSL",
        "pypng",
        "PyYAML",
        "qrcode",
        "reportlab",
        "Pillow",
        "multiformats",
        "PyNaCl",
        "py-multicodec",
    ],
    extras_require={
        'test': test_requires
    },
    author="eReuse.org team",
    author_email="cayo@puigdefabregas.eu",
    description="signature and validation of verifiable credential and verifiable presentation",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://farga.pangea.org/ereuse/pyvckit",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.9',
)
