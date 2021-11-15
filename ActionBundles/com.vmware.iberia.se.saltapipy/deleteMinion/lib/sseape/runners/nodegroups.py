# coding: utf-8
'''
Import master nodegroups into SaltStack Enterprise as target groups
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
import salt.exceptions
import salt.utils.minions

# Import SSEAPE libs
from sseape.utils.client import make_api_client

log = logging.getLogger(__name__)


def sse_import(*args, **kwargs):
    '''
    Send defined nodegroups to SSE
    '''
    # Get existing target group names
    try:
        client = make_api_client(__opts__)
        tgts = client.api.tgt.get_target_group().ret
    except RPCError as exc:
        msg = 'Request failed: {0}'.format(exc)
        log.error(msg)
        raise salt.exceptions.SaltException(msg)
    except NotConnectable as exc:
        msg = 'Request failed: {0}: {1}'.format(exc.code, exc.message)
        log.error(msg)
        raise salt.exceptions.SaltException(msg)
    existing = [tgt['name'] for tgt in tgts['results']]

    # Send up to SSE, skipping any that match existing target groups
    ret = {}
    master = __opts__['id']
    nodegroups = __opts__['nodegroups']
    for name in nodegroups:
        if name in existing:
            log.info('Skipping nodegroup %s which matches an existing target group name', name)
            ret[name] = False
        else:
            comp = salt.utils.minions.nodegroup_comp(name, nodegroups)
            if isinstance(comp, list):
                comp = ' '.join(comp)
            tgt = {
                'name': name,
                'desc': 'Imported from nodegroup {0} on master {1}'.format(name, master),
                'tgt': {
                    master: {
                        'tgt_type': 'compound',
                        'tgt': comp
                    }
                }
            }
            try:
                response = client.api.tgt.save_target_group(**tgt)
                log.info('Imported nodegroup %s (%s)', name, response.ret)
                ret[name] = True
            except NotConnectable as exc:
                log.error('Request failed: %s', str(exc))
                ret[name] = False
            except RPCError as exc:
                log.error('Request failed: %s: %s', exc.code, exc.message)
                ret[name] = False
    return ret
