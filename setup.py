from setuptools import setup, find_packages

with open("requirements.txt", "r") as _f:
    requirements = [line for line in _f.read().split("\n")]

setup(
    name="imapbackup38",
    description="A Python script for creating full backups of IMAP mailboxes",
    packages=find_packages(),
    author="Rui Carmo",
    entry_points="""
    [console_scripts]
    imapbackup38=imapbackup38:main
    """,
    py_modules=["imapbackup38"],
    install_requires=requirements,
    version="0.0.1",
    url="https://github.com/rcarmo/imapbackup",
)