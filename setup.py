from setuptools import setup, find_packages

setup(
    name="authutils",
    version="3.0.3",
    description="Gen3 auth utility functions",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        "addict>=2.1.1,<3.0.0",
        "Authlib>=0.4.1,<1.0.0",
        "Flask>=0.10.1",
        "requests>=2.6.0,<3.0.0",
        "python-keystoneclient==1.8.1",
        "PyJWT>=1.5.3,<2.0.0",
        "PyYAML>=3.11",
        "Werkzeug>=0.12.2",
        "xmltodict>=0.9.2",
        "cached-property>=1.4.3",
        "cdislogging",
        "cdiserrors>=0.1.0",
    ],
)
