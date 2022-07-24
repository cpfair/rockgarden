#!/usr/bin/env python

import os
from distutils.core import setup

setup(name='Rock Garden',
      version='0.2',
      description='Patch Pebble apps',
      author='Collin Fair',
      url='https://github.com/cpfair/rockgarden',
      packages=['rockgarden'],
      package_data={
        'rockgarden': [
            'mods_layout.template.ld',
            'mods_proxy.template.s',
            os.path.join('c_src', 'message_keys.auto.h'),
        ],
      },
      install_requires=["six"]
     )
