#!/usr/bin/env python

from distutils.core import setup

setup(name='Rock Garden',
      version='0.1',
      description='Patch Pebble apps',
      author='Collin Fair',
      url='https://github.com/cpfair/rockgarden',
      packages=['rockgarden'],
      package_data={
          'rockgarden': ['mods_layout.template.ld', 'mods_proxy.template.s'],
      },
      install_requires=["six"]
     )
