#!/usr/bin/env python
'''
Created on Dec 12, 2015

@author: rob

See LICENSE for licensing information
'''

from distutils.core import setup

setup(name='PrivCount',
      version='1.0.2',
      description='Safely gather and aggregate Tor statistics',
      url='https://github.com/privcount',
      author='Rob Jansen, Tim Wilson-Brown',
      packages=['privcount'],
      scripts=['privcount/tools/privcount'],
      # allow other packages to depend on "privcount [plot]"
      extras_require={
        'plot':  ['matplotlib', 'numpy']
      }
     )
