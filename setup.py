from setuptools import setup

with open("README.md") as f:
    README = f.read()


setup(
    name="python-binexport",
    version="0.2.1",
    description="Python wrapper to manipulate binexport files (protobuf)",
    long_description_content_type='text/markdown',
    long_description=README,
    author="Robin David",
    author_email="rdavid@quarkslab.com",
    url="https://github.com/quarkslab/python-binexport",
    packages=["binexport"],
    python_requires=">=3.9",
    project_urls={
        "Documentation": "https://quarkslab.github.io/diffing-portal/exporter/binexport.html#python-binexport",
        "Bug Tracker": "https://github.com/quarkslab/python-binexport/issues",
        "Source": "https://github.com/quarkslab/python-binexport"
    },
    install_requires=[
        "python-magic",
        "click",
        "protobuf",
        "networkx",
        "enum_tools",
        "idascript"
    ],
    scripts=["bin/binexporter"],
    license="AGPL-3.0",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
)
