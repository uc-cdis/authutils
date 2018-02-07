from setuptools import setup, find_packages

setup(
    name="authutils",
    version='0.0.1',
    description="Gen3 auth utility functions.",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        'cdislogging',
        'cdiserrors',
        'cdispyutils',
        'datamodelutils',
        'gdcdatamodel',
        'userdatamodel',
        'Flask==0.10.1',
        'Flask-SQLAlchemy-Session>=1.1,<2.0',
        'requests>=2.6.0,<3.0.0',
        'python-keystoneclient==1.8.1',
        'PyYAML==3.11',
        'sqlalchemy==0.9.9',
        'Werkzeug==0.12.2',
        'xmltodict==0.9.2',
    ],
    dependency_links=[
        'git+https://git@github.com/uc-cdis/cdislogging.git@master#egg=cdislogging',
        'git+https://git@github.com/uc-cdis/cdis-python-utils.git@0.2.2#egg=cdispyutils',
        'git+https://git@github.com/uc-cdis/cdiserrors.git@0.0.4#egg=cdiserrors',
        'git+https://git@github.com/NCI-GDC/gdcdatamodel.git@1.12.0#egg=gdcdatamodel',
        'git+https://git@github.com/uc-cdis/userdatamodel.git@cb7143c709a1173c84de4577d3e866318a2cc834#egg=userdatamodel',
        'git+https://git@github.com/uc-cdis/datamodelutils.git@0.3.0#egg=datamodelutils', # second-hand dependency
    ],
)
