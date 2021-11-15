# -*- coding: utf-8 -*-
'''
Engine to convert rabbitmq feed to events on the Salt Event bus.

.. versionadded: 2016.3.0

To setup, add the following to the proxy config.

.. code-block:: yaml

    engines:
      - hpeov:
          route: 'scmb.alerts.#'

:depends: amqp
'''

# Copyright (C) 2020 SaltStack, Inc.
#
# This file is licensed only for use with SaltStack's Enterprise software
# product and may not be used for any other purpose without prior written
# authorization from SaltStack, Inc.  The license terms governing your use of
# Salt Stack Enterprise also govern your use of this file. See license terms at
# https://www.saltstack.com/terms/

# Import Python libs
from __future__ import absolute_import
import functools
import json
import logging
import os
import ssl

# Import Salt libs
import salt.utils.event

try:
    import amqp
    HAS_RABBITMQ = True
except ImportError:
    HAS_RABBITMQ = False

log = logging.getLogger(__name__)


def __virtual__():
    return HAS_RABBITMQ and 'hpeov.ping' in __proxy__


def _callback(channel, msg):
    # ACK receipt of message
    channel.basic_ack(msg.delivery_tag)

    # Convert from json into a Python dictionary
    body = json.loads(msg.body)

    # Create a new variable name 'resource' to point to the
    # nested resource dictionary inside of the body
    resource = body['resource']

    if __opts__.get('__role') == 'master':
        fire_master = salt.utils.event.get_master_event(
            __opts__,
            __opts__['sock_dir']).fire_event
    else:
        fire_master = None

    def fire(tag, msg):
        if fire_master:
            fire_master(msg, tag)
        else:
            __salt__['event.send'](tag, msg)

    import pprint  # pylint: disable=import-outside-toplevel
    log.debug(pprint.pformat(body))
    if 'associatedResource' in body['resource']:
        uri = body['resource']['associatedResource']['resourceUri'].strip('/')
    elif 'uri' in body['resource']:
        uri = body['resource']['uri'].strip('/')
    else:
        uri = body['resourceUri']

    fire(os.path.join('salt/engines/hpeov', uri), body)

    # Cancel this callback
    if msg.body == 'quit':
        channel.basic_cancel(msg.consumer_tag)


def _recv(host, port, exchange, route=None, queue=None, with_ssl=False,
         ca_certs=None, certfile=None, keyfile=None):
    if exchange is None:
        exchange = 'message'
    if route is None:
        route = 'example.text'

    if with_ssl is True:
        # Setup our ssl options
        ssl_options = ({'ca_certs': ca_certs or '/tmp/caroot.pem',
                        'certfile': certfile or '/tmp/client.pem',
                        'keyfile': keyfile or '/tmp/key.pem',
                        'cert_reqs': ssl.CERT_REQUIRED if with_ssl is True else ssl.CERT_NONE,
                        'ssl_version': ssl.PROTOCOL_TLSv1_1,
                        'server_side': False})

        # Connect to RabbitMQ
        conn = amqp.Connection(':'.join([host, port]), login_method='EXTERNAL', ssl=ssl_options)
    else:
        conn = amqp.Connection(':'.join([host, port]), login_method='EXTERNAL')

    ch = conn.channel()
    if queue is None:
        queue, _, _ = ch.queue_declare()
    ch.queue_bind(queue, exchange, route)
    ch.basic_consume(queue, callback=functools.partial(_callback, ch))

    # Start listening for messages
    while ch.callbacks:
        ch.wait()

    ch.close()
    conn.close()


def start(route=None):
    # get rabbit ssl certificates
    log.info('Starting SCMB->Salt Event Bus Engine')
    __proxy__['hpeov.get_cert_ca']()
    __proxy__['hpeov.get_rabbit_keypair']()

    host = __opts__['proxy']['host']
    port = __opts__['proxy'].get('port', '5671')
    route = route or 'scmb.alerts.#'
    exchange = 'scmb'

    _recv(host=host, port=port, exchange=exchange, route=route, with_ssl=True)
