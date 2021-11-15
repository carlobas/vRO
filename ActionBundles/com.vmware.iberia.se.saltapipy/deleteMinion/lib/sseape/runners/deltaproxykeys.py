# -*- coding: utf-8 -*-
'''
Runner for handling keys for deltaproxies.
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
import logging
import os

# Import Salt libs
import salt.config
import salt.exceptions
import salt.modules.file
import salt.runner

log = logging.getLogger(__file__)


def _softlink_keys(id, deltaproxies):

    linked = []
    wheel = salt.wheel.WheelClient(__opts__)
    pki_path = __opts__['pki_dir']
    curdir = os.getcwd()
    os.chdir(os.path.join(pki_path, 'minions'))
    try:
        for dp_key in deltaproxies:
            wheel.functions['key.delete'](dp_key)
            try:
                os.unlink(dp_key)
            except OSError:
                pass
            os.symlink(id, dp_key)
            linked.append(dp_key)
    finally:
        os.chdir(curdir)

    return linked


def _unsoftlink_keys(id):

    wheel = salt.wheel.WheelClient(__opts__)
    pki_path = __opts__['pki_dir']
    unsoftlinked = []
    keydirs = ['minions', 'minions_pre', 'minions_autosign', 'minions_denied', 'minions_rejected']
    for keydir in keydirs:
        for root, dirs, files in os.walk(os.path.join(pki_path, keydir)):
            for file in files:
                try:
                    controlproxy_id = os.readlink(os.path.join(root, file))
                    if controlproxy_id == id:
                        wheel.functions['key.delete'](file)
                        # Key is deleted but softlink does not get removed
                        try:
                            os.unlink(os.path.join(root, file))
                        except OSError:
                            pass
                        unsoftlinked.append(file)
                except OSError:
                    pass
    return unsoftlinked


def _get_pillar(minion, **kwargs):

    pillarenv = None
    saltenv = 'base'
    id_, grains, _ = salt.utils.minions.get_minion_data(minion, __opts__)
    if grains is None:
        grains = {'fqdn': minion}

    for key in kwargs:
        if key == 'saltenv':
            saltenv = kwargs[key]
        elif key == 'pillarenv':
            # pillarenv overridden on CLI
            pillarenv = kwargs[key]
        else:
            grains[key] = kwargs[key]

    pillar = salt.pillar.Pillar(
        __opts__,
        grains,
        id_,
        saltenv,
        pillarenv=pillarenv)

    compiled_pillar = pillar.compile_pillar()

    # needed because pillar compilation clobbers grains etc via lazyLoader
    # this resets the masterminion back to known state
    __salt__['salt.cmd']('sys.reload_modules')

    return compiled_pillar


def update(id=None):
    r'''
    Look at the passed minion ID, and if it is a control proxy, check pillar for
    the deltaproxies underneath it.  If there are none, make sure all softlinks to this
    key are removed.  If there is no key with this ID, also make sure there are no
    dangling symlinks in the keys directory

    If this control proxy is responsible for deltaproxies, symlink all these keys to
    the one for this minion_id.
    '''
    if not id:
        raise salt.exceptions.SaltRunnerError('deltaproxykeys.update must be passed id=')
    this_pillar = _get_pillar(id)

    removed = _unsoftlink_keys(id)

    try:
        if this_pillar['proxy']['proxytype'] != 'deltaproxy':
            raise KeyError
        linked = _softlink_keys(id, this_pillar['proxy']['ids'])
        result = True
    except KeyError:
        # make sure there are no softlinked keys
        _unsoftlink_keys(id)
        result = False
        log.debug('un-softlinking keys for %s', id)

    ret = {'success': result,
           'removed': removed,
           'linked': linked}
    return ret
