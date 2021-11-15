# -*- coding: utf-8 -*-
'''
Initialize Master RSA Key for authentication.
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
import ctypes
import logging
import os
import shutil
import time
from multiprocessing import Value
from threading import Thread

# Import SSEAPE libs
import sseape.utils.config as sseape_config
from sseape.utils.client import make_api_client, make_http_client
from sseape.utils.compat import fopen

PRINTED_WARNING = Value(ctypes.c_float, 0.0)
log = logging.getLogger(__name__)


def acquire_lock(lock_name, opts):
    try:
        client = make_http_client(opts)
        ret = client.get_lock(lock_name)

    except Exception as e:  # pylint: disable=broad-except
        log.error('Error getting raas lock.')
        log.error(e, exc_info=True)
        return False

    else:
        return ret['acquired']


def rotate_pubkey(opts):
    pubkey_path = sseape_config.get(opts, 'sseapi_pubkey_path')
    lock_name = '{}-rotatekey'.format(opts['id'])
    # rotate key by default every 24 hours
    cycle = opts.get('sseapi_key_rotation', 60 * 60 * 24)

    while 1:
        if os.path.exists(pubkey_path):
            break

        time.sleep(30)

    mtime = os.path.getmtime(pubkey_path)
    future_time = mtime + cycle
    wait = future_time - time.time()
    if wait > 30:
        time.sleep(wait)

    else:
        time.sleep(30)

    mtime = os.path.getmtime(pubkey_path)
    if (time.time() - mtime) >= cycle:
        acquired = acquire_lock(lock_name, opts)
        if acquired:
            log.info('Rotating key: %s', pubkey_path)
            master_id = opts['id']
            try:
                client = make_api_client(opts)
                ret = client.api.master.rotate_master_key(master_id=master_id).ret

            except Exception as e:  # pylint: disable=broad-except
                log.error('Error rotating public key.')
                log.error(e, exc_info=True)

            else:
                if 'pubkey' in ret and 'fingerprint' in ret:
                    orig_mask = os.umask(0o277)
                    new_key_path = pubkey_path + '.new'
                    with fopen(new_key_path, 'w') as fh:
                        fh.write(ret['pubkey'])
                    shutil.move(new_key_path, pubkey_path)
                    os.umask(orig_mask)
                    log.info('Key saved %s', ret['fingerprint'])

                else:
                    log.error('Error rotating public key, pubkey not in return %s.', ret)


def init_pubkey_loop(opts, clear_key=False):
    pubkey_path = sseape_config.get(opts, 'sseapi_pubkey_path')
    while 1:
        lock_name = '{}-pubkey'.format(opts['id'])
        acquired = acquire_lock(lock_name, opts)

        if acquired:
            if clear_key:
                log.info('Reinitializing public key.')
                os.remove(pubkey_path)
                clear_key = False

            client = make_http_client(opts)
            client.request_master_key(master_id=client.username)
            break

        time.sleep(10)
        if os.path.exists(pubkey_path):
            break


def check_key(opts):
    pubkey_path = sseape_config.get(opts, 'sseapi_pubkey_path')
    mtime = os.path.getmtime(pubkey_path)
    old = time.time() - mtime
    if old <= 300:
        # only do the check every 5 minutes at the most
        return

    client = make_api_client(opts)
    response = client.get_master_jwt(test=True, init_xsrf=True)
    if response:
        if 'ret' in response and response['ret'] and 'master_id' in response['ret']:
            # everything good, pubkey works
            return

        elif 'error' in response and response['error'] and 'code' in response['error']:
            code = response['error']['code']
            if code == 4006:
                # status is known, key doesn't work
                start_thread(init_pubkey_loop, opts, clear_key=True)


def start_thread(func, *args, **kwargs):
    t = Thread(target=func, args=args, kwargs=kwargs)
    t.daemon = True
    t.start()


def init_pubkey(opts):
    '''
    Initialize key and prevent multiple processes from initializing at the same time.
    '''

    pubkey_path = sseape_config.get(opts, 'sseapi_pubkey_path')
    username = opts.get('sseapi_username', None)
    password = opts.get('sseapi_password', None)

    if username and password:
        now = time.time()
        # show every 24 hours
        old = PRINTED_WARNING.value + 60 * 60 * 24
        if now > old:
            PRINTED_WARNING.value = now
            log.error('!' * 80)
            log.error('Password authentication has been deprecated for masters.')
            log.error('Remove sseapi_username and sseapi_password from your config')
            log.error('to upgrade to key authentication.')
            log.error('!' * 80)

        return

    if os.path.exists(pubkey_path):
        check_key(opts)

    else:
        start_thread(init_pubkey_loop, opts)

    start_thread(rotate_pubkey, opts)
