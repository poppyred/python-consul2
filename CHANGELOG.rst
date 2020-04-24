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
-----

Features
~~~~~~~~
* timeout added to http requests <https://github.com/poppyred/python-consul2/pull/4>
* handle CONSUL_HTTP_ADDR including a http:// or https:// scheme  <https://github.com/poppyred/python-consul2/pull/3>

0.1.0
-----

* Changed ACL token from params/body to headers. v1.7+ of consul now rejects unknown json payload
fields (https://discuss.hashicorp.com/t/consul-1-7-0-released/5866) and the current API version
recommends using headers for token instead of parameters. (https://www.consul.io/api/index.html)

