import glob
import os
import re
import sys

from setuptools import setup
from setuptools.command.install import install
from setuptools.command.test import test as testcommand

metadata = dict(
    re.findall("__([a-z]+)__ = '([^']+)'", open('consul/__init__.py').read()))

requirements = [
    x.strip() for x
    in open('requirements.txt').readlines() if not x.startswith('#')]

description = "Python client for Consul (http://www.consul.io/)"

py_modules = [os.path.splitext(x)[0] for x in glob.glob('consul/*.py')]


class Install(install):
    def run(self):
        # Issue #123: skip installation of consul.aio if python version < 3.4.2
        # as this version or later is required by aiohttp
        if sys.version_info < (3, 4, 2):
            if 'consul/aio' in self.distribution.py_modules:
                self.distribution.py_modules.remove('consul/aio')
        install.run(self)


class PyTest(testcommand):
    def finalize_options(self):
        testcommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


setup(
    name='python-consul2-hh',
    version=metadata['version'],
    author='yan.gao',
    author_email='373251686@qq.com',
    url='https://github.com/poppyred/python-consul2',
    license='MIT',
    description=description,
    long_description='{0}\n\n{1}'.format(
        open('README.rst').read(),  # noqa
        open('CHANGELOG.rst').read()
    ),
    py_modules=py_modules,
    install_requires=requirements,
    extras_require={
        'tornado': ['tornado'],
        'asyncio': ['aiohttp'],
        'twisted': ['twisted', 'treq'],
    },
    tests_require=['pytest', 'pytest-twisted'],
    cmdclass={'test': PyTest,
              'install': Install},
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
