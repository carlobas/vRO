# -*- coding: utf-8 -*-
'''
Job Completion Engine

This engine watches the event bus and posts a new event when it appears that a
job has finished running.

Note that this is an educated guess as to when the job completed--if some
targeted minions are not connected, dead, overloaded, or otherwise unavailable
we will just hit the timeout.  Job completion event itself will contain
responded and non-responded minions.

'''

# Copyright (C) 2020 SaltStack, Inc.
#
# This file is licensed only for use with SaltStack's Enterprise software
# product and may not be used for any other purpose without prior written
# authorization from SaltStack, Inc.  The license terms governing your use of
# Salt Stack Enterprise also govern your use of this file. See license terms at
# https://www.saltstack.com/terms/

# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals
import fnmatch
import logging
import time

# Import Salt libs
import salt.client
import salt.key
import salt.utils.event
import salt.utils.process

log = logging.getLogger(__name__)


def start():

    key_manager = salt.key.Key(__opts__)
    minion_new_job_event_match = 'salt/job/*/new'
    minion_job_ret_event_match = 'salt/job/*/ret/*'
    gather_job_timeout = int(__opts__['gather_job_timeout'])
    inflight = {}
    completed = {}

    event_bus = salt.utils.event.get_master_event(__opts__,
                                                  __opts__['sock_dir'],
                                                  listen=True)

    client = salt.client.get_local_client(mopts=__opts__)

    event_bus.subscribe(minion_new_job_event_match)

    while True:
        event = event_bus.get_event(full=True)
        now = time.time()
        if event is not None:
            log.trace('tag: %s', event['tag'])
            if (fnmatch.fnmatch(event['tag'], minion_new_job_event_match) and
                    event['data']['fun'] != 'saltutil.find_job'):
                event_bus.subscribe('salt/job/{}/ret/*'.format(event['data']['jid']))

                tagparts = event['tag'].split('/')
                jid = tagparts[2]
                if jid in completed:
                    continue
                minions = event.get('data', {}).get('minions', None)
                inflight[jid] = {'__payload': {'returning': False}}
                log.debug('salt.engines.jobcompletion: New job--jid: %s, '
                          'fun: %s, minions: %s',
                          jid, event['data']['fun'], minions)

                for minion in minions:
                    inflight[jid].setdefault(minion, {})
                    inflight[jid][minion].setdefault('done', False)
                    inflight[jid][minion].setdefault('waiting_on_find_job', False)
                    inflight[jid][minion]['last_seen'] = now
                    inflight[jid].setdefault('__payload', {})
                    inflight[jid]['__payload']['fun'] = event['data']['fun']
                    inflight[jid]['__payload']['arg'] = event['data']['arg']

            if (fnmatch.fnmatch(event['tag'], minion_new_job_event_match) and
                    event['data']['fun'] == 'saltutil.find_job'):
                find_job_jid = event['data']['jid']
                jid = event['data']['arg'][0]
                event_bus.subscribe('salt/job/{}/ret/*'.format(find_job_jid))
                event_bus.subscribe('salt/job/{}/ret/*'.format(jid))
                minions = event['data']['minions']
                log.debug(
                    'salt.engines.jobcompletion: find_job found--jid: %s, minions: %s',
                    jid, minions)

                if jid in completed:
                    continue
                inflight.setdefault(jid, {})
                for minion in minions:
                    inflight[jid].setdefault(minion, {})
                    inflight[jid][minion]['waiting_on_find_job'] = True
                    inflight[jid][minion]['find_job_jid'] = find_job_jid
                    inflight[jid][minion]['last_seen'] = now

            if (fnmatch.fnmatch(event['tag'], minion_job_ret_event_match) and
                    event['data']['fun'] != 'saltutil.find_job'):
                jid = event['data']['jid']
                if jid in completed:
                    continue
                minion = event['data']['id']
                inflight.setdefault(jid, {})
                inflight[jid].setdefault(minion, {})
                inflight[jid][minion]['waiting_on_find_job'] = False
                inflight[jid][minion]['done'] = True
                log.debug(
                    'salt.engines.jobcompletion: return found--jid: %s, minions: %s',
                    jid, minion)
                inflight[jid].setdefault('__payload', {})
                if not inflight[jid]['__payload'].get('returning'):
                    inflight[jid]['__payload']['returning'] = True
                    salt.utils.event.get_master_event(__opts__, __opts__['sock_dir']).fire_event(data={}, tag='salt/job/{}/returning'.format(jid))

            if (fnmatch.fnmatch(event['tag'], minion_job_ret_event_match) and
                    event['data']['fun'] == 'saltutil.find_job'):
                find_job_jid = event['data']['jid']
                jid = event['data']['fun_args'][0]
                if jid in completed:
                    continue
                minions = event['data'].get('minions', [event['data'].get('id')])
                try:
                    # Sometimes we appear to get here without ever actually subscribing
                    event_bus.unsubscribe(
                        'salt/job/{}/ret/*'.format(event['data']['jid']))
                except ValueError:
                    pass
                inflight.setdefault(jid, {})
                for minion in minions:
                    inflight[jid].setdefault(minion, {})
                    inflight[jid][minion]['waiting_on_find_job'] = False
                    inflight[jid][minion]['find_job_jid'] = find_job_jid
                    inflight[jid][minion]['last_seen'] = now

        # Report status of jobs inflight/completed
        for jid in list(inflight):
            all_minions = set(inflight[jid]).difference(set(['__payload']))
            returned_minions = set()
            missing_minions = set()
            need_status_minions = set()
            for minion_id in all_minions:
                minion_status = inflight[jid][minion_id]
                if minion_status.get('done', False):
                    returned_minions.add(minion_id)
                else:
                    last_seen = minion_status.get('last_seen', now)
                    if last_seen + gather_job_timeout + 1 < now:
                        if minion_status.get('waiting_on_find_job', False):
                            missing_minions.add(minion_id)
                        else:
                            need_status_minions.add(minion_id)
                            inflight[jid][minion_id]['waiting_on_find_job'] = True
                            inflight[jid][minion_id]['last_seen'] = now

            log.debug('salt.engines.jobcompletion: jid %s: returned: %s, missing: %s, need_status: %s, all: %s',
                      jid,
                      list(returned_minions),
                      list(missing_minions),
                      list(need_status_minions),
                      list(all_minions))
            if returned_minions | missing_minions == all_minions:
                # All minions accounted for, missing or returned
                try:
                    # Sometimes we appear to get here without ever actually subscribing
                    event_bus.unsubscribe('salt/job/{}/ret/*'.format(jid))
                except ValueError:
                    pass
                payload = inflight[jid].get('__payload', {})
                data = {'returned': list(returned_minions),
                        'missing': list(missing_minions),
                        'fun': payload.get('fun', ''),
                        'arg': payload.get('arg', '')}
                salt.utils.event.get_master_event(__opts__, __opts__['sock_dir']).fire_event(data=data, tag='salt/job/{}/complete'.format(jid))
                for minion in all_minions:
                    find_job_jid = inflight[jid][minion].get('find_job_jid', False)
                    if find_job_jid:
                        try:
                            # Sometimes we appear to get here without ever actually subscribing
                            event_bus.unsubscribe('salt/job/{}/ret/*'.format(find_job_jid))
                        except ValueError:
                            pass
                log.debug('jid %s is complete', jid)

                completed[jid] = time.time()
                del inflight[jid]
                continue

            # These minions have not returned and we have not seen a find_job for them
            # This means there has probably been no find_job sent for them so this was a call from a client that doesn't send
            # find_jobs (like RaaS, or salt --async).  We'll send our own
            if need_status_minions:
                keys = key_manager.list_status('accepted')
                keys = set(keys.get('minions', []))
                need_status_minions_with_keys = need_status_minions & keys
                if need_status_minions != need_status_minions_with_keys:
                    log.debug('About to find_job for jid %s and minions %s but this master does not have keys for %s',
                              jid, str(need_status_minions), str(need_status_minions - need_status_minions_with_keys))

                if not need_status_minions_with_keys:
                    log.debug('About to find_job for jid %s but this master has no keys for %s', jid, str(need_status_minions))
                else:
                    client.run_job(tgt=list(need_status_minions_with_keys),
                                   fun='saltutil.find_job',
                                   arg=[jid],
                                   tgt_type='list')

        # Trim old jids from the completed list
        old = now - 3600
        trim = [jid for jid in completed if completed[jid] < old]
        for jid in trim:
            del completed[jid]
