from setuptools import setup, find_packages

setup(
    name="authutils",
    version='0.0.1',
    description="The auth system for PlanX.",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        'cdis_oauth2client',
        'cdislogging',
        'cdiserrors',
        'cdispyutils',
        'datamodelutils',
        'userdatamodel',
        'Flask',
        'Flask-SQLAlchemy-Session',
        'requests',
        'python-keystoneclient',
        'PyYAML',
        'sqlalchemy',
        'Werkzeug',
        'xmltodict',
    ],
)
