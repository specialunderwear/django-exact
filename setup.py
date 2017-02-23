# -*- coding: utf-8 -*-
from setuptools import setup

setup(
	name='django-exact',

	# Versions should comply with PEP440.  For a discussion on single-sourcing
	# the version across setup.py and the project code, see
	# https://packaging.python.org/en/latest/single_source_version.html
	version='0.1',

	description='Django storage and authentication view for exactonline',
	long_description='Django storage and authentication view for https://github.com/ossobv/exactonline',

	# The project's main homepage.
	url='https://github.com/affiliprint/django-exact',

	# Author details
	author='Malte Böhme, Affiliprint Deutschland GmbH',
	author_email='malte.boehme@affiliprint.com',

	# Choose your license
	license='MIT',

	# You can just specify the packages manually here if your project is
	# simple. Or you can use find_packages().
	packages=["exact"],

	# Alternatively, if you want to distribute just a my_module.py, uncomment
	# this:
	#   py_modules=["my_module"],

	# List run-time dependencies here.  These will be installed by pip when
	# your project is installed. For an analysis of "install_requires" vs pip's
	# requirements files see:
	# https://packaging.python.org/en/latest/requirements.html
	install_requires=['exactonline'],
)