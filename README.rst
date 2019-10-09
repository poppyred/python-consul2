Python client for `Consul.io <http://www.consul.io/>`_
======================================================

|Build Status|
|License Status|
|Pypi Status|
|Pyversions Status|
|Docs Status|
|Coverage Status|

Example
-------

.. code:: python

    import consul

    c = consul.Consul()

    # poll a key for updates
    index = None
    while True:
        index, data = c.kv.get('foo', index=index)
        print data['Value']

    # in another process
    c.kv.put('foo', 'bar')

Installation
------------

::

    pip install python-consul2
    
**Note:** When using python-consul library in environment with proxy server, setting of ``http_proxy``, ``https_proxy`` and ``no_proxy`` environment variables can be required for proper functionality.

.. |Build Status|
   image:: https://travis-ci.org/poppyred/python-consul2.svg?branch=master&style=flat-square
   :target: https://travis-ci.org/poppyred/python-consul2

.. |License Status|
   image:: https://img.shields.io/pypi/l/python-consul2
   :target: https://github.com/poppyred/python-consul2/blob/master/LICENSE

.. |Pypi Status|
   image:: https://img.shields.io/pypi/v/python-consul2
   :target: https://pypi.org/project/python-consul2/

.. |Pyversions Status|
   image:: https://img.shields.io/pypi/pyversions/python-consul2
   :target: https://pypi.org/project/python-consul2/

.. |Docs Status|
   image:: https://img.shields.io/readthedocs/python-consul2
   :target: https://python-consul2.readthedocs.io/





.. |Coverage Status1|
   image:: https://codecov.io/gh/poppyred/python-consul2/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/poppyred/python-consul2

.. |Coverage Status|
   image:: https://codecov.io/gh/poppyred/python-consul2/branch/dev/graph/badge.svg
   :target: https://codecov.io/gh/poppyred/python-consul2

Status
------
This `python-consul <https://github.com/cablehead/python-consul>`_ author may be a little busy, I will maintain a version
`python-consul2 <https://github.com/poppyred/python-consul2>`_,
welcome to use. The new consul version was used(v1.6.1). Progressively
implement all API interfaces in the future

There's a few API endpoints still to go to expose all features available in
Consul v1.6.1. If you need an endpoint that's not in the documentation, just
open an issue and I'll try and add it straight away.

Mailing List
------------

- 373251686@qq.com

Contributing
------------

python-consul2 is currently maintained by:

- @poppyred


Please reach out if you're interested in being a maintainer as well. Otherwise,
open a PR or Issue we'll try and respond as quickly as we're able.

Issue Labels
~~~~~~~~~~~~

:today!: Some triaging is in progress and this issue should be taken care of in
         a couple of hours!

:priority: There's a clear need to address this issue and it's likely a core
           contributor will take it on. Opening a PR for these is greatly
           appreciated!

:help wanted: This issue makes sense and would be useful. It's unlikely a core
              contributor will get to this though, so if you'd like to see it
              addressed please open a PR.

:question: The need for the issue isn't clear or needs clarification, so please
           follow up.  Issues in this state for a few months, without
           responses will likely will be closed.

PRs
~~~

Pull requests are very much appreciated! When you create a PR please ensure:

#. All current tests pass, including flake8
#. To add tests for your new features, if reasonable
#. To add docstrings for new api features you add and if needed link to these
   docstrings from the sphinx documentation

Releases
~~~~~~~~

.. code:: bash

    # release the current version, eg: 0.6.1-dev -> 0.6.1
    bumpversion release

    # prepare the next patch (z-stream) version, eg: 0.6.1 -> 0.6.2-dev
    bumpversion --no-tag patch

    # else, prepare the next minor (y-stream) version, eg: 0.6.1 -> 0.7.0-dev
    bumpversion --no-tag minor
