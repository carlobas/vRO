# -*- coding: utf-8 -*-
'''
    salt.roster.sseapi_roster
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    RaaS roster backend
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

log = logging.getLogger(__name__)

__virtualname__ = 'sseapi'


def __virtual__():
    if '__role' not in __opts__:
        return False, 'Unable to find out the role(master or minion)'
    if __opts__['__role'] != 'master':
        return (False,
                'The SSEApi roster is meant to run on the salt-master, '
                'not on {0}'.format(__opts__['__role']))
    return (False, 'Not yet implemented')


def targets(tgt, tgt_type, **kwargs):
    pass
