Change log
==========

0.0.1
-----

Features
~~~~~~~~
* forked from cablehead/python-consul
* Fix  `Consul.ACL` support


0.0.4
-----

Features
~~~~~~~~
* implement Connect Config Snapshot  consul_api


0.0.5
-----

Features
~~~~~~~~
* implement all consul http-api


0.0.8
-----

Features
~~~~~~~~
* Add TLSSkipVerify for HTTPS check <bhuisgen@hbis.fr>

0.0.16
-------

Features
~~~~~~~~
* Timeout added to http requests <https://github.com/poppyred/python-consul2/pull/4>
* Handle CONSUL_HTTP_ADDR including a http:// or https:// scheme  <https://github.com/poppyred/python-consul2/pull/3>

0.0.17
-------

Features
~~~~~~~~
* removes the WriteRequest in the json body where used. <https://www.consul.io/docs/upgrade-specific.html#stricter-json-decoding>
* refactors the api token to use the `X-Consul-Token` header instead of a parameter, which is recommended and more secure.
* Fix catalog.register node_meta in data not in params <https://github.com/poppyred/python-consul2/issues/11>
* Fix #7 #9 #10 #11

0.1.0
------

Features
~~~~~~~~
* `long_description` has syntax errors in markup and would not be rendered on PyPI.
