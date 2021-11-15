# -*- coding: utf-8 -*-
'''
The RAAS Returner
'''

# Copyright (C) 2020 SaltStack, Inc.
#
# This file is licensed only for use with SaltStack's Enterprise software
# product and may not be used for any other purpose without prior written
# authorization from SaltStack, Inc.  The license terms governing your use of
# Salt Stack Enterprise also govern your use of this file. See license terms at
# https://www.saltstack.com/terms/

# Import Python libs
from __future__ import absolute_import, unicode_literals
import base64
import copy
import logging
import random

# Import 3rd-party libs
from sseapiclient.exc import NotConnectable, RPCError

# Import Salt libs
import salt.serializers.msgpack
import salt.utils.jid
from salt.exceptions import CommandExecutionError
from salt.serializers import DeserializationError, SerializationError

# Import SSEAPE libs
import sseape.utils.config as sseape_config
from sseape.utils.client import make_api_client

log = logging.getLogger(__name__)

__virtualname__ = 'sseapi'

BASE64_PREFIX = 'b64:'


def __virtual__():
    if '__role' not in __opts__:
        return False, 'Unable to find out the role(master or minion)'
    if __opts__['__role'] not in ('master', 'syndic'):
        return (False,
                'The SSEApi returner is meant to run on the salt-master, '
                'not on {0}'.format(__opts__['__role']))
    return True


def _event_queue_enabled(strategy):
    '''
    Check if event queue is enabled in the config
    '''
    ret = False
    if (sseape_config.get(__opts__, 'sseapi_event_queue.strategy') == strategy and
        'sseapi_local_queue.push' in __salt__):
        ret = True
    return ret


def _send_events_to_queue(events):
    '''
    Push events onto the queue
    '''
    queue = sseape_config.get(__opts__, 'sseapi_event_queue.name')
    try:
        items = [{'data': event} for event in events]
        __salt__['sseapi_local_queue.push'](queue=queue, items=items)
    except CommandExecutionError as exc:
        log.error('Error writing events to queue: %s', str(exc))


def _rpc_queue_enabled(strategy):
    '''
    Check if RPC queue is enabled in the config
    '''
    ret = False
    if (sseape_config.get(__opts__, 'sseapi_rpc_queue.strategy') == strategy and
        'sseapi_local_queue.push' in __salt__):
        ret = True
    return ret


def _send_rpc_to_queue(payload):
    '''
    Push an RPC payload onto the queue
    '''
    queue = sseape_config.get(__opts__, 'sseapi_rpc_queue.name')
    try:
        items = [{'data': payload}]
        __salt__['sseapi_local_queue.push'](queue=queue, items=items)
    except CommandExecutionError as exc:
        log.error('Error writing RPC payload to queue: %s', str(exc))


def _gen_jid(passed_jid):
    if passed_jid is not None:
        return passed_jid
    # Generate a JID
    try:
        jid = salt.utils.jid.gen_jid(__opts__)  # pylint: disable=too-many-function-args
    except TypeError:
        jid = salt.utils.jid.gen_jid()  # pylint: disable=no-value-for-parameter
    # Return the same JID with randomized microseconds
    return '{0}{1:06d}'.format(jid[:-6], random.randint(0, 999999))


def _encode_binary_fields(obj):
    '''
    Encode binary fields in a json-friendly way in an otherwise
    json-serializable object
    '''
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            key2 = _encode_binary_fields(key)
            value2 = _encode_binary_fields(obj[key])
            if key2 != key:
                obj.pop(key)
                obj[key2] = value2
            elif value2 != obj[key]:
                obj[key] = value2
        return obj
    if isinstance(obj, list):
        for (idx, item) in enumerate(obj):
            item2 = _encode_binary_fields(item)
            if item2 != item:
                obj[idx] = item2
        return obj
    if isinstance(obj, bytes):
        return BASE64_PREFIX + base64.b64encode(obj).decode()
    return obj


def _decode_binary_fields(obj):
    '''
    Undo the effects of _encode_binary_fields()
    '''
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            key2 = _decode_binary_fields(key)
            value2 = _decode_binary_fields(obj[key])
            if key2 != key:
                obj.pop(key)
                obj[key2] = value2
            elif value2 != obj[key]:
                obj[key] = value2
        return obj
    if isinstance(obj, list):
        for (idx, item) in enumerate(obj):
            item2 = _decode_binary_fields(item)
            if item2 != item:
                obj[idx] = item2
        return obj
    if isinstance(obj, str) and obj.startswith(BASE64_PREFIX):
        try:
            obj = base64.b64decode(obj[len(BASE64_PREFIX):])
        except (TypeError, ValueError):
            pass
        return obj
    return obj


def get_client():
    if 'sseapi_client' not in __context__:
        __context__['sseapi_client'] = make_api_client(__opts__)
    return __context__['sseapi_client']


def returner(ret):
    '''
    Return a job to the SSEApi server
    '''
    pass  # pylint: disable=unnecessary-pass


def save_load(jid, load, minions=None):
    '''
    Save the pub load
    '''
    load2 = copy.deepcopy(load)
    _encode_binary_fields(load2)

    if _rpc_queue_enabled('always'):
        payload = {
            'resource': 'ret',
            'method': 'save_load',
            'kwargs': {
                'master_id': __opts__['id'],
                'jid': jid,
                'load': load2
            }
        }
        _send_rpc_to_queue(payload)
    else:
        try:
            get_client().api.ret.save_load(__opts__['id'], jid, load=load2)
        except (NotConnectable, RPCError) as exc:
            log.error('Failed to save load: %s', exc)
            log.debug('Load which failed to be saved: %r', load)

    try:
        key = '{}/{}'.format(__opts__['id'], jid)
        value = salt.serializers.msgpack.serialize(load2)
        __salt__['sseapi_local_cache.set'](cache='load', key=key, value=value)
    except (CommandExecutionError, SerializationError) as exc:
        log.error('Failed to save load %s to local cache: %s', key, str(exc))


def get_jid(jid):
    '''
    Return information about the given jid
    '''
    try:
        return get_client().api.ret.get_jid(str(jid), master_id=__opts__['id']).ret
    except (NotConnectable, RPCError) as exc:
        log.error('Failed to get JID: %s', exc, exc_info_on_loglevel=logging.DEBUG)


def get_load(jid):
    '''
    Return information about the given jid
    '''
    load = None
    try:
        key = '{}/{}'.format(__opts__['id'], jid)
        value = __salt__['sseapi_local_cache.get'](cache='load', key=key)
        load = salt.serializers.msgpack.deserialize(value)
        if load:
            log.info('Returning load %s from local cache', key)
        else:
            log.info('No load %s found in local cache', key)
    except (CommandExecutionError, DeserializationError) as exc:
        log.info('Failed to get load %s from local cache: %s', key, str(exc))

    if not load:
        try:
            load = get_client().api.ret.get_load(__opts__['id'], str(jid)).ret
        except (NotConnectable, RPCError) as exc:
            log.error('Failed to get load: %s', exc, exc_info_on_loglevel=logging.DEBUG)

    if load:
        load = _decode_binary_fields(load)
    return load


def get_fun(fun):
    '''
    Return a dict of the named func being called on all minions
    '''
    try:
        return get_client().api.ret.get_fun(fun).ret
    except (NotConnectable, RPCError) as exc:
        log.error('Failed to get fun: %s', exc, exc_info_on_loglevel=logging.DEBUG)


def get_jids():
    '''
    return a list of jids
    '''

    try:
        ret = get_client().api.ret.get_jids().ret
        for jid, load in ret.items():
            ret[jid] = salt.utils.jid.format_jid_instance(jid, load)
        return ret
    except (NotConnectable, RPCError) as exc:
        log.error('Failed to get JIDs: %s', exc, exc_info_on_loglevel=logging.DEBUG)
    return {}


def get_minions():
    '''
    Return a list of minions
    '''
    try:
        return get_client().api.ret.get_minions().ret
    except (NotConnectable, RPCError) as exc:
        log.error('Failed to get minions: %s', exc, exc_info_on_loglevel=logging.DEBUG)


def event_return(events):
    '''
    Send a list of events up to RAAS!
    '''
    for event in events:
        _encode_binary_fields(event)
        event['data'].setdefault('_master_path', []).append(__opts__['id'])

    if _event_queue_enabled('always'):
        _send_events_to_queue(events)
    else:
        try:
            get_client().api.ret.save_event(__opts__['id'], events)
        except (NotConnectable, RPCError) as exc:
            log.error('Failed to save events: %s', exc, exc_info_on_loglevel=logging.DEBUG)
            if _event_queue_enabled('on_failure'):
                _send_events_to_queue(events)


def prep_jid(nocache=False, passed_jid=None):  # pylint: disable=unused-argument
    '''
    Do any work necessary to prepare a JID, including sending a custom jid
    '''
    return _gen_jid(passed_jid)
