'''
Created on Dec 12, 2015

@author: rob
'''

#!/usr/bin/env python

from distutils.core import setup

setup(name='Privex',
      version='0.0.1',
      description='Safely gather and aggregate Tor statistics',
      author='Rob Jansen',
      packages=['privex'],
      scripts=['privex/privex'],
     )