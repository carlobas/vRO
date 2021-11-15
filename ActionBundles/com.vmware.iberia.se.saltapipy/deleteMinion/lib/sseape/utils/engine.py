# coding: utf-8
'''
RaaS engine utils
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
import time

# Import 3rd-party libs
from sseapiclient.exc import NotConnectable, RequestFailure

# Import Salt libs
import salt.loader
from salt.exceptions import CommandExecutionError

# Import SSEAPE libs
import sseape.utils.config as sseape_config
from sseape.utils.client import make_api_client

LAST_PUSH_TIMESTAMP = 'last_push'

__salt__ = None

log = logging.getLogger(__name__)


class QueueEngineBase(object):
    '''
    Base class for engines that queue things and send them to raas periodically
    '''

    def __init__(self, config_name, opts=None, raas_client=None):
        global __salt__
        if __salt__ is None:
            __salt__ = salt.loader.minion_mods(opts)

        self.config_name = config_name
        self.opts = opts
        self.raas_client = raas_client
        self.last_vacuum = 0.0

        def get_config(name):
            return sseape_config.get(self.opts, '{}.{}'.format(self.config_name, name))

        self.name = get_config('name')
        self.strategy = get_config('strategy')
        self.push_interval = get_config('push_interval')
        self.batch_limit = get_config('batch_limit')
        self.age_limit = get_config('age_limit')
        self.size_limit = get_config('size_limit')
        self.vacuum_interval = get_config('vacuum_interval')
        self.vacuum_limit = get_config('vacuum_limit')
        self.forward = get_config('forward')
        if not self.forward:
            self.forward = []
        elif not isinstance(self.forward, list):
            self.forward = [self.forward]

    def _purge_entries(self, queue):
        '''
        Purge old entries from a queue to enforce age and size limits
        '''
        try:
            purged = __salt__['sseapi_local_queue.purge'](queue, age_limit=self.age_limit)
            if purged > 0:
                log.warning('%s: queue %s: discarded %d items due to age limit', self.config_name, queue, purged)
            last_push = self._get_metadata(queue, LAST_PUSH_TIMESTAMP)
            if last_push:
                purged = __salt__['sseapi_local_queue.purge'](queue, age_limit_abs=last_push)
                if purged > 0:
                    log.info('%s: queue %s: discarded %d items due to last push timestamp (likely duplicates)',
                            self.config_name, queue, purged)
            purged = __salt__['sseapi_local_queue.purge'](queue, size_limit=self.size_limit)
            if purged > 0:
                log.warning('%s: queue %s: discarded %d items due to size limit', self.config_name, queue, purged)
        except CommandExecutionError as exc:
            log.error('%s: queue %s: failed to purge old entries: %s', self.config_name, queue, str(exc))

    def _pop_entries(self, queue):
        '''
        Pop entries from a queue for sending to raas
        '''
        try:
            return __salt__['sseapi_local_queue.pop'](queue, self.batch_limit)
        except CommandExecutionError as exc:
            log.error('%s: queue %s: failed to pop entries: %s', self.config_name, queue, str(exc))

    def _push_entries(self, queue, entries):
        '''
        Push entries back onto a queue, presumably because the send failed
        '''
        try:
            __salt__['sseapi_local_queue.push'](queue, entries)
        except CommandExecutionError as exc:
            log.error('%s: queue %s: failed to push entries: %s', self.config_name, queue, str(exc))

    def _get_metadata(self, queue, key):
        '''
        Get a queue metadata item
        '''
        try:
            return __salt__['sseapi_local_queue.get_metadata'](queue, key)
        except CommandExecutionError as exc:
            log.error('%s: queue %s: failed to get metadata item %s: %s', self.config_name, queue, key, str(exc))

    def _set_metadata(self, queue, key, value):
        '''
        Set a queue metadata item
        '''
        try:
            __salt__['sseapi_local_queue.set_metadata'](queue, key, value)
        except CommandExecutionError as exc:
            log.error('%s: queue %s: failed to set metadata item %s=%s: %s',
                    self.config_name, queue, key, value, str(exc))

    def _process_entries(self):
        '''
        Pop entries from the primary queue, send them to raas, and push them to
        configured forwarding queues.
        '''
        entries = None
        last_push = None
        try:
            self._purge_entries(self.name)
            entries = self._pop_entries(self.name)
            if entries:
                log.info('%s: retrieved %d entries from primary queue', self.config_name, len(entries))
                last_push = self.send_entries(entries)
                self._set_metadata(self.name, LAST_PUSH_TIMESTAMP, last_push)
            else:
                log.info('%s: no entries to send to SSE', self.config_name)
        except Exception as exc:  # pylint: disable=broad-except
            if last_push is None and entries:
                log.error('%s: failed to send entries to SSE (will requeue): %s', self.config_name, str(exc))
                self._push_entries(self.name, entries)

        if entries:
            for queue in self.forward:
                log.info('%s: queue %s: pushing %d entries', self.config_name, queue, len(entries))
                self._push_entries(queue, entries)

    def _forward_entries(self):
        '''
        Pop entries from each configured forwarding queue and forward them
        '''
        for queue in self.forward:
            entries = None
            last_push = None
            try:
                self._purge_entries(queue)
                entries = self._pop_entries(queue)
                if entries:
                    log.info('%s: queue %s: retrieved %d entries', self.config_name, queue, len(entries))
                    last_push = self.forward_entries(queue, entries)
                    self._set_metadata(queue, LAST_PUSH_TIMESTAMP, last_push)
                else:
                    log.info('%s: queue %s: no entries to forward', self.config_name, queue)
            except Exception as exc:  # pylint: disable=broad-except
                if last_push is None and entries:
                    log.error('%s: queue %s: failed to forward entries (will requeue): %s',
                            self.config_name, queue, str(exc))
                    self._push_entries(queue, entries)

    def _vacuum_if_due(self):
        '''
        Try to vacuum queue databases if it's time
        '''
        now = time.time()
        if now > self.last_vacuum + self.vacuum_interval:
            # Vacuum the primary queue
            try:
                if __salt__['sseapi_local_queue.vacuum'](self.name, self.vacuum_limit):
                    self.last_vacuum = now
            except CommandExecutionError as exc:
                log.error('%s: failed to vacuum primary queue database: %s', self.config_name, str(exc))

            # Vacuum forwarding queues
            for queue in self.forward:
                try:
                    __salt__['sseapi_local_queue.vacuum'](queue, self.vacuum_limit)
                except CommandExecutionError as exc:
                    log.error('%s: queue %s: failed to vacuum database: %s', self.config_name, queue, str(exc))

    def send_entries(self, entries):
        '''
        Derived class implementations should
        - send queue entries to raas
        - return the timestamp of the most recent entry successfully sent to raas
        - raise an exception on failure, which will cause entries to be re-queued
        '''
        raise NotImplementedError

    def forward_entries(self, queue, entries):
        '''
        Send events to a "forward" destination. Base class handles exceptions.
        '''
        raise NotImplementedError

    def start(self):
        while True:
            log.info('Start %s engine iteration...', self.config_name)

            if not __salt__['sseapi_local_queue.queue_exists'](self.name):
                log.info('%s: primary queue does not exist, skipping this iteration', self.config_name)
                time.sleep(self.push_interval)
                continue

            if self.raas_client is None:
                try:
                    self.raas_client = make_api_client(self.opts)
                except (NotConnectable, RequestFailure) as exc:
                    log.error('%s: could not connect to SSE server: %s', self.config_name, str(exc))
                    time.sleep(self.push_interval)
                    continue

            start = time.time()
            try:
                self._process_entries()
                self._forward_entries()
                self._vacuum_if_due()
            except Exception as exc:  # pylint: disable=broad-except
                log.info('%s: engine iteration interrupted with exception: %s',
                        self.config_name, exc, exc_info=True)
            duration = time.time() - start

            # If the iteration ran longer than the interval, sleep a little anyway
            stime = self.push_interval - duration
            if stime < 0:
                log.warning('%s: engine iteration time (%.1fs) exceeded push interval (%.1fs)',
                        self.config_name, duration, self.push_interval)
                stime = min(5, self.push_interval / 5)

            # Sleep before the next iteration.
            log.info('%s: engine sleeping for %.1f seconds', self.config_name, stime)
            time.sleep(stime)
