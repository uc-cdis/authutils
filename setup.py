from setuptools import setup, find_packages

setup(
    name="authutils",
    version='3.0.0',
    description="Gen3 auth utility functions",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        "Authlib[crypto]==0.4.1",
        'cdislogging',
        'cdiserrors',
        'Flask==0.10.1',
        'requests>=2.6.0,<3.0.0',
        'python-keystoneclient==1.8.1',
        'PyYAML>=3.11,<4.0',
        'Werkzeug==0.12.2',
        'xmltodict==0.9.2',
        'cached-property>=1.4.3',
    ],
    dependency_links=[
        'git+https://git@github.com/uc-cdis/cdislogging.git@master#egg=cdislogging',
        'git+https://git@github.com/uc-cdis/cdiserrors.git@0.0.4#egg=cdiserrors',
    ],
)
