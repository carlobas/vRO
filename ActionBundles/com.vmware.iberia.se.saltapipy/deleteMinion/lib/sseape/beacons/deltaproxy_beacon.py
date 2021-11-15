# -*- coding: utf-8 -*-
'''
Beacon for collecting stats on deltaproxy load
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
import logging
import os
import re

# Import Salt libs
import salt.utils.platform  # pylint: disable=no-name-in-module
from salt.ext.six.moves import map

log = logging.getLogger(__name__)
proxy_rgx = re.compile(r'.*proxyid=(.*)$')

__virtualname__ = 'deltaproxy'

HAS_PSUTIL = False
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def __virtual__():
    if salt.utils.platform.is_windows():
        return (False, 'This beacon is not currently compatible with Windows')
    if not HAS_PSUTIL:
        return (False, 'This beacon needs psutil')
    return __virtualname__


def validate(config):
    '''
    Validate the beacon configuration.
    '''
    return True, 'Valid beacon configuration'


def _proxyid():
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

    for pid in pids:
        try:
            with salt.utils.fopen(os.path.join('/proc', pid, 'cmdline'), 'rb') as cmd:
                cmdline = cmd.read()
            if 'salt-proxy' in cmdline:
                for arg in cmdline.split('\0'):
                    matches = proxy_rgx.match(arg)
                    if matches:
                        return matches.group(1)
        except IOError:
            continue
    return ''


def beacon(config):
    '''
    Emit various resource utilization values useful for deltaproxy load balancing.

    Not currently user configurable.
    Maybe in the future, but for now we just attempt to keep an even balance.
    '''
    log.trace('deltaproxy beacon starting')

    _config = {}
    list(map(_config.update, config))

    cpu = psutil.cpu_percent()  # pylint: disable=undefined-variable
    mem = psutil.virtual_memory()[2]  # pylint: disable=undefined-variable
    proxyid = _proxyid()

    return [{'cpu': cpu, 'mem': mem, 'proxyid': proxyid}]
