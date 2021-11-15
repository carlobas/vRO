# -*- coding: utf-8 -*-
'''
RaaS external pillar
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

# Import 3rd-party libs
from sseapiclient.exc import NotConnectable, RPCError

# Import Salt libs
import salt.utils.minions
from salt.exceptions import CommandExecutionError
from salt.serializers import DeserializationError, SerializationError

# Import SSEAPE libs
import sseape.utils.config as sseape_config
from sseape.utils.client import make_api_client

log = logging.getLogger(__name__)

__virtualname__ = 'sseapi'


def __virtual__():
    if '__role' not in __opts__:
        return False, 'Unable to find out the role(master or minion)'
    if __opts__['__role'] == 'minion' and '_ssh_version' not in __opts__:
        return (False,
                'The SSEApi pillar is meant to run on the salt-master, '
                'not on {0}'.format(__opts__['__role']))
    return True


def get_client():
    if 'sseapi_client' not in __context__:
        __context__['sseapi_client'] = make_api_client(__opts__)
    return __context__['sseapi_client']


def _get_pillar(pillar_uuid):
    '''
    Get a single named pillar
    '''
    log.debug('Get pillar with UUID: %s', pillar_uuid)
    try:
        response = get_client().api.pillar.get_pillars(pillar_uuid=pillar_uuid).ret
        return response['results'][0]['pillar']
    except (NotConnectable, RPCError) as exc:
        log.error('Failed to get pillar(%s): %s', pillar_uuid, str(exc))
        return {}


def _get_pillars(pillar_uuids):
    '''
    Iterate over pillar names and return all pillars in the list
    '''
    log.debug('Get pillar data for pillar UUID\'s %s', pillar_uuids)
    pillar_dict = {}
    for pillar_uuid in pillar_uuids:
        pillar_dict.update(_get_pillar(pillar_uuid))
    return pillar_dict


def _get_target_groups():
    '''
    Get target groups from local cache or from raas
    '''
    # Look in local cache first
    try:
        ret = __salt__['sseapi_local_cache.get_many'](cache='tgt', keypat='%')
        targets = [salt.serializers.msgpack.deserialize(x[1]) for x in ret]
    except (CommandExecutionError, DeserializationError) as exc:
        log.info('Failed to get target groups from local cache: %s', str(exc))
        targets = []

    # Get target groups from raas if necessary
    if not targets:
        log.debug('Get target groups from sseapi_server')
        page = 0
        while True:
            try:
                ret = get_client().api.tgt.get_target_group(page=page, limit=500).ret
                if ret['results']:
                    targets.extend(ret['results'])
                    page += 1
                else:
                    break
            except (NotConnectable, RPCError) as exc:
                log.error('Failed to get target groups: %s', str(exc))
                targets = []
                break

        # Save to local cache
        if targets:
            try:
                items = []
                for idx, tgt in enumerate(targets):
                    key = 'tgt-{}'.format(idx)
                    value = salt.serializers.msgpack.serialize(tgt)
                    items.append((key, value))
                __salt__['sseapi_local_cache.set_many'](cache='tgt', items=items)
            except (CommandExecutionError, SerializationError) as exc:
                log.error('Failed to save %d target groups to local cache: %s', len(targets), str(exc))

    return targets


# Note: This function is called once for each minion that fetches it's pillar
#       data.
def ext_pillar(minion_id,
               pillar,
               *args,
               **kwargs):
    '''
    Read pillar data from RaaS via its API
    '''
    try:
        sseapi_server = sseape_config.get(__opts__, 'sseapi_server')
        master_id = __opts__['id']
        cluster_id = __opts__.get('sseapi_cluster_id')
    except KeyError:
        log.critical('SSEApi pillar not configured correctly')
        return {}

    targets = _get_target_groups()
    sseapi_pillar = {}
    if targets:
        log.debug('Target groups: %s', targets)
        # Process each target
        for target in targets:
            target_id = target.get('name') or target.get('uuid')
            log.debug('Checking target %s: %s', target_id, target)
            # Skip the target if there are no pillars associated with it.
            pillar_uuids = target.get('pillars')
            if not pillar_uuids:
                log.debug('Target %s has no associated pillars', target_id)
                continue
            if isinstance(target.get('tgt'), dict):
                master_tgt = (target['tgt'].get('*') or
                              target['tgt'].get(master_id) or
                              target['tgt'].get(cluster_id))
                if not master_tgt:
                    log.debug('Target %s is not assigned to master %s', target_id, master_id)
                    continue
                tgt_type = master_tgt.get('tgt_type', 'glob')
                tgt = master_tgt.get('tgt')
            else:
                masters = target.get('masters')
                if masters and master_id not in masters:
                    log.debug('Target %s is not assigned to master %s', target_id, master_id)
                    continue
                tgt_type = target.get('tgt_type', 'glob')
                tgt = target.get('tgt')
            log.debug('Target %s is assigned to master %s', target_id, master_id)
            log.debug('Check if minion_id %s matches target %s, tgt_type %s', minion_id, tgt, tgt_type)
            ckminions = salt.utils.minions.CkMinions(__opts__)
            # Current list valid expr_form:
            # Letter | Matcher Name
            # -------|-------------
            #     'R'| all_minions
            #        | glob
            #     'L'| list
            #     'E'| pcre
            #        | cache
            #     'G'| grain
            #     'P'| grain_pcre
            #     'I'| pillar
            #     'J'| pillar_pcre
            #        | pillar_exact
            #     'S'| ipcidr
            #        | range
            #        | compound_pillar_exact
            #        | compound
            # TODO: decide what will be stored in the tgt_type and create a
            #     map that maps a single character to the Matcher Name
            #     doing so will allow us to change function names w/o
            #     breaking the REST API. For now, just use the Matcher
            #     Names above.
            match = ckminions.check_minions(tgt, tgt_type)
            if isinstance(match, dict):
                # Salt > v2017.7.x
                # https://github.com/saltstack/salt/pull/42915
                match = match['minions']
            if minion_id in match:
                log.debug('Minion ID \'%s\' was found in match: %s', minion_id, match)
                sseapi_pillar.update(_get_pillars(pillar_uuids))
            else:
                log.debug('Minion ID \'%s\' was NOT found in match: %s', minion_id, match)
    return sseapi_pillar
