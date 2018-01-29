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
        'gdcdatamodel',
        'userdatamodel',
        'Flask==0.10.1',
        'Flask-SQLAlchemy-Session==1.1',
        'requests==2.7.0',
        'python-keystoneclient==1.8.1',
        'PyYAML==3.11',
        'sqlalchemy==0.9.9',
        'Werkzeug==0.12.2',
        'xmltodict==0.9.2',
    ],
)
