# coding: utf-8
'''
RaaS client utils
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

# Import 3rd-party libs
from sseapiclient import APIClient
from sseapiclient.httpclient import HTTPClient

# Import Salt libs
import salt.utils.verify
try:
    from salt.utils.user import get_user as salt_get_user
except ImportError:
    from salt.utils import get_user as salt_get_user

# Import SSEAPE libs
import sseape.utils.config as sseape_config
from sseape.utils.compat import fopen

log = logging.getLogger(__name__)


class SharedJWT(object):
    def __init__(self, opts):
        # Verify that the cachedir exists
        salt.utils.verify.verify_env([opts['cachedir']], salt_get_user())
        self.file = os.path.join(opts['cachedir'], 'auth_token.jwt')

    def get(self):
        try:
            with fopen(self.file, 'r') as fh:
                line = fh.readline()
                if line:
                    log.debug('Previous JWT used: %s', self.file)
                    return line
        except (IOError, OSError) as exc:
            log.debug('Failed to load JWT: %s', exc)
        return None

    def set(self, jwt):
        log.info('Creating new JWT: %s', self.file)
        with fopen(self.file, 'w') as fh:
            return fh.write(jwt)

    def remove(self):
        # previously we would check for the file existence before
        # removing.  Small race where we could remove the file after
        # checking for existence.  Then the remove would throw an exception
        # which would abort the flow.  We don't really care if the file is here
        # or not if we get to this point, so just remove it and catch the exception
        try:
            os.remove(self.file)
            log.info('Removed JWT: %s', self.file)
        except (IOError, OSError) as exc:
            log.debug('Failed to remove JWT: %s', exc)


def _get_client_kwargs(opts, rpc_api_version=None):
    username = opts.get('sseapi_username', None) or opts['id']
    timeout = max(opts.get('sseapi_timeout', 200),
                  opts.get('sseapi_connect_timeout', 5),
                  opts.get('sseapi_request_timeout', 15))
    ssl_validate_cert = opts.get('sseapi_ssl_validate_cert',
                                 # Support the old setting value
                                 opts.get('sseapi_validate_cert', True))
    return {
        'server': sseape_config.get(opts, 'sseapi_server'),
        'username': username,
        'password': opts.get('sseapi_password', None),
        'config_name': opts.get('sseapi_config_name', 'internal'),
        'timeout': timeout,
        'use_jwt': True,
        'shared_jwt': SharedJWT(opts),
        'pubkey_path': sseape_config.get(opts, 'sseapi_pubkey_path'),
        'cookies_path': os.path.join(opts['cachedir'], 'sse-client.cookies'),
        'rpc_api_version': rpc_api_version,
        'ssl_key': opts.get('sseapi_ssl_key', None),
        'ssl_cert': opts.get('sseapi_ssl_cert', None),
        'ssl_validate_cert': ssl_validate_cert,
    }


def make_http_client(opts, rpc_api_version=None):
    kwargs = _get_client_kwargs(opts, rpc_api_version=rpc_api_version)
    return HTTPClient(**kwargs)


def make_api_client(opts, rpc_api_version=None):
    kwargs = _get_client_kwargs(opts, rpc_api_version=rpc_api_version)
    return APIClient(**kwargs)
