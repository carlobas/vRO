# coding: utf-8
'''
The SSE Event Queue engine

Periodically get events from the local event queue and send them to raas
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

__virtualname__ = 'eventqueue'
log = logging.getLogger(__name__)


def __virtual__():
    if '__role' not in __opts__:
        return False, 'Unable to find out the role(master or minion)'
    if __opts__['__role'] != 'master':
        return (False,
                'The SSE Event Queue engine is meant to run on the salt-master, '
                'not on {0}'.format(__opts__['__role']))
    if 'sseapi_event_queue' in __opts__ and __opts__['sseapi_event_queue'].get('strategy') in ('always', 'on_failure'):
        return True
    else:
        return False, 'SSE Event queue not enabled.'


class EventQueueEngine(QueueEngineBase):

    def __init__(self, opts=None, raas_client=None, returners=None):

        super(EventQueueEngine, self).__init__(config_name='sseapi_event_queue',
                                               opts=opts,
                                               raas_client=raas_client)

        if returners is None:
            self.returners = salt.loader.returners(self.opts, __salt__)
        else:
            self.returners = returners

    def send_entries(self, entries):
        '''
        Send events to raas. Base class handles exceptions.
        '''
        events = [item['data'] for item in entries]
        self.raas_client.api.ret.save_event(self.opts['id'], events)

        # Return the timestamp of the newest successfully pushed entry
        return max([item['timestamp'] for item in entries])

    def forward_entries(self, queue, entries):
        '''
        Send events to a "forwarding" returner. Base class handles exceptions.
        '''
        events = [item['data'] for item in entries]
        event_return = '{}.event_return'.format(queue)
        if event_return in self.returners:
            try:
                log.info('Forwarding %d entries to %s', len(events), event_return)
                self.returners[event_return](events)
            except Exception as exc:  # pylint: disable=broad-except
                log.error('Could not forward entries: %s raised an exception: %s', event_return, exc)
                raise
        else:
            log.error('Could not forward entries: %s not found', event_return)


def start(raas_client=None, returners=None):
    '''
    Start the engine
    '''
    opts = globals().get('__opts__')
    if opts is None:
        opts = salt.config.master_config(os.path.join(salt.syspaths.CONFIG_DIR, 'master'))

    EventQueueEngine(opts, raas_client=raas_client, returners=returners).start()
