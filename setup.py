#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

from ck_wifikiller.config import Configuration

setup(
    name='ck-wifikiller',
    version=Configuration.version.replace('-ck', ''),
    author='传康Kk',
    author_email='1837620622@qq.com',
    url='https://github.com/cknb6/ck-wifikiller',
    packages=find_packages(include=['ck_wifikiller', 'ck_wifikiller.*']),
    include_package_data=True,
    package_data={
        'ck_wifikiller': [],
    },
    data_files=[
        ('share/ck-wifikiller/wordlists', [
            'wordlists/ck-default-wpa.txt',
            'wordlists/wpa-top4800.txt',
        ]),
    ],
    entry_points={
        'console_scripts': [
            'ck-wifikiller = ck_wifikiller.__main__:entry_point',
            'ckwifikiller = ck_wifikiller.__main__:entry_point',
        ]
    },
    scripts=['bin/ck-wifikiller'],
    license='GNU GPLv2',
    description='Wireless auditor for modern Kali — fork of wifite2 (PMKID/22000/Kismet recon)',
    long_description=(
        'ck-wifikiller automates wireless auditing on modern Kali Linux. '
        'Fork of derv82/wifite2 with hashcat -m 22000, hcxpcapngtool, '
        'Layer-1 recon orchestration (Kismet/bettercap), and improved wordlists. '
        'Authorized testing only.'
    ),
    python_requires='>=3.8',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: POSIX :: Linux',
        'Topic :: Security',
        'Environment :: Console',
    ],
)
