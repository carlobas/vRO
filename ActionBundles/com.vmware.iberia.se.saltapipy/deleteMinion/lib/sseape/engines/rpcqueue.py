# coding: utf-8
'''
The SSE RPC Queue engine

Periodically get entries from the local RPC queue and send them to raas
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
import logging
import os

# Import Salt libs
import salt.config
import salt.loader
import salt.syspaths

# Import SSEAPE libs
from sseape.utils.engine import QueueEngineBase

__virtualname__ = 'rpcqueue'
log = logging.getLogger(__name__)


def __virtual__():
    if '__role' not in __opts__:
        return False, 'Unable to find out the role(master or minion)'
    if __opts__['__role'] != 'master':
        return (False,
                'The SSE RPC Queue engine is meant to run on the salt-master, '
                'not on {0}'.format(__opts__['__role']))
    if 'sseapi_rpc_queue' in __opts__ and __opts__['sseapi_rpc_queue'].get('strategy') in ('always', 'on_failure'):
        return True
    else:
        return False, 'SSE RPC queue not enabled.'


class RPCQueueEngine(QueueEngineBase):

    def __init__(self, opts=None, raas_client=None):

        super(RPCQueueEngine, self).__init__(config_name='sseapi_rpc_queue',
                                             opts=opts,
                                             raas_client=raas_client)

    def send_entries(self, entries):
        '''
        Send RPC calls to raas. Base class handles exceptions.
        '''
        calls = [item['data'] for item in entries]
        self.raas_client.call_many(calls)

        # Return the timestamp of the newest successfully pushed entry
        return max([item['timestamp'] for item in entries])

    def forward_entries(self, queue, entries):
        log.error('Forwarding not implemented for rpcqueue')


def start(raas_client=None):
    '''
    Start the engine
    '''
    opts = globals().get('__opts__')
    if opts is None:
        opts = salt.config.master_config(os.path.join(salt.syspaths.CONFIG_DIR, 'master'))

    RPCQueueEngine(opts, raas_client).start()
