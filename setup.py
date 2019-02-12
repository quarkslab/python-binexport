
from setuptools import setup

setup(
    name='python-binexport',
    version='0.1',
    description='Python wrapper to manipulate binexport files (protobuf)',
    author='Robin David',
    author_email='rdavid@quarkslab.com',
    url='https://gitlab.qb/rdavid/python-binexport',
    packages=['binexport'],
    install_requires=[
        'python-magic',
        'click',
        'protobuf',
        'networkx',
        'idascript'
    ],
    scripts=['bin/binexporter']
)
