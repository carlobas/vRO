# -*- coding: utf-8 -*-
'''
    sseape.utils.config
    ~~~~~~~~~~~~~~~~~~~

    SSEAPE configuration
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
import io
import logging
import os

# Import 3rd-party libs
import yaml

# Import Salt libs
import salt.config
import salt.syspaths

# Import SSEAPE libs
import sseape.loader

try:
    import salt.utils.stringutils
    to_str = salt.utils.stringutils.to_str
    to_unicode = salt.utils.stringutils.to_unicode
except ImportError:
    import salt.utils
    to_str = salt.utils.to_str
    to_unicode = salt.utils.to_unicode

log = logging.getLogger(__name__)

EXT_DIRS_TEMPLATE = '''\
# Beacons External Modules Path(s)
{beacons_dirs}

# Engines External Modules Path(s)
{engines_dirs}

# Fileserver External Modules Path(s)
{fileserver_dirs}

# Pillar External Modules Path(s)
{pillar_dirs}

# Returner External Modules Path(s)
{returner_dirs}

# Roster External Modules Path(s)
{roster_dirs}

# Runner External Modules Path(s)
{runner_dirs}

# Salt External Modules Path(s)
{module_dirs}

# Proxy External Modules Path(s)
{proxy_dirs}

# Metaproxy External Modules Path(s)
{metaproxy_dirs}

# States External Modules Paths(s)
{states_dirs}

'''

CONFIG_TEMPLATE = '''\
# Assign an ID to your master
#id: master1

# Salt command timeout
timeout: {timeout}

# Enable SSE engines
engines:
  - sseapi: {{}}
  - eventqueue: {{}}
  - rpcqueue: {{}}
  - jobcompletion: {{}}

# Enable SSE master job cache and event returner (sseapi or sse_pgjsonb)
master_job_cache: {returner}
event_return: {returner}
{returner_config}
# Enable SSE external pillar
ext_pillar:
  - sseapi: {{}}

# Enable SSE fileserver backend
fileserver_backend:
  - sseapi
  - roots

sseapi_update_interval: {fs_update_interval}                  # SSE fileserver update interval, in seconds

'''

SSE_PGJSONB_CONFIG = '''
# Configure direct-to-PostgreSQL returner
returner.sse_pgjsonb.host: localhost
returner.sse_pgjsonb.user: root
returner.sse_pgjsonb.pass: salt
returner.sse_pgjsonb.db: raas_83eef44162444c0dbb161f13a15dacd3
returner.sse_pgjsonb.port: 5432
'''

# Options ordered as they should appear in the generated default config
SSEAPE_OPTS = (
    {
        'name': 'sseapi_server',
        'default': 'http://localhost:8080',
        'comment': 'URL of SSE server',
        'tweak': lambda val: val.rstrip('/'),
    },
    {
        'name': 'sseapi_pubkey_path',
        'default': lambda opts: os.path.join(opts['pki_dir'], 'sseapi_key.pub'),
        'comment': 'Path to public key for authenticating to SSE server',
    },
    {
        'name': 'sseapi_key_rotation',
        'default': 24*3600,
        'comment': 'Authentication key rotation interval, in seconds',
    },
    {
        'name': 'sseapi_config_name',
        'default': 'internal',
        'comment': 'SSE server credentials, not required if using key authentication',
    },
    {
        'name': 'sseapi_username',
        'default': None,
    },
    {
        'name': 'sseapi_password',
        'default': None,
    },
    {
        'name': 'sseapi_force_restfull',
        'default': False,
        'comment': 'Set to True to use http/s only, no upgrade to WebSocket',
        'hidden': True,  # obsolete
    },
    {
        'name': 'sseapi_ssl_ca',
        'default': None,
        'comment': 'Path to a CA file or directory',
        'hidden': True,  # obsolete
    },
    {
        'name': 'sseapi_ssl_key',
        'default': None,
        'comment': "Path to the certificate's private key",
    },
    {
        'name': 'sseapi_ssl_cert',
        'default': None,
        'comment': 'Path to the certificate',
    },
    {
        'name': 'sseapi_ssl_validate_cert',
        'default': True,
        'comment': 'Set to False to disable certificate validation',
    },
    {
        'name': 'sseapi_validate_cert',
        'default': True,
        'hidden': True,  # obsolete, use sseapi_ssl_validate_cert
    },
    {
        'name': 'sseapi_connect_timeout',
        'default': 5,
        'comment': 'Timeout for initial connection, in seconds',
        'hidden': True,  # obsolete
    },
    {
        'name': 'sseapi_request_timeout',
        'default': 15,
        'comment': 'Timeout for request, in seconds',
        'hidden': True,  # obsolete
    },
    {
        'name': 'sseapi_timeout',
        'default': 200,
        'comment': 'Timeout for SSE request, in seconds',
    },
    {
        'name': 'sseapi_max_message_size',
        'default': 10*1024*1024,
        'comment': 'Max websocket message size, in bytes',
        'hidden': True,  # obsolete
    },
    {
        'name': 'sseapi_websocket_ping_interval',
        'default': 15,
        'comment': 'Websocket connection ping interval, in seconds',
        'hidden': True,  # obsolete
    },
    {
        'name': 'sseapi_websocket_ping_timeout',
        'default': 600,
        'comment': 'Websocket connection ping timeout, in seconds',
        'hidden': True,  # obsolete
    },
    {
        'name': 'sseapi_cluster_id',
        'default': None,
        'comment': 'SSE cluster ID for this master (optional)',
    },
    {
        'name': 'sseapi_failover_master',
        'default': False,
        'comment': 'Set to True if this is a failover master',
    },
    {
        'name': 'sseapi_poll_interval',
        'default': 30,
        'comment': 'Interval for retrieving commands from SSE and reporting grains & fs changes',
    },
    {
        'name': 'sseapi_cache_pillar',
        'default': False,
        'comment': 'Set to True to enable caching of pillar data in SSE',
    },
    {
        'name': 'sseapi_max_minion_grains_payload',
        'default': 2000,
        'comment': 'The maximum minion grains payload to send per iteration, in minions',
    },
    {
        'name': 'fileserver.sseapi.cache_timeout',
        'default': 1,
        'comment': 'SSE fileserver local cache timeout, in minutes',
    },
    {
        'name': 'io_loop_blocking_log_threshold',
        'default': None,
        'hidden': True,  # for troubleshooting, do not use in production
    },
    {
        'name': 'sseapi_event_queue',
        'comment': 'Queue events locally and send to SSE in batches',
        'default': (
            {
                'name': 'name',
                'default': 'sseapi-events',
                'comment': 'Event queue name',
            },
            {
                'name': 'strategy',
                'default': 'never',
                'comment': 'When to queue events: always, on_failure, never',
            },
            # Queue defaults should be set together, e.g.:
            #
            #   push_interval: 5
            #   batch_limit: 2000
            #   age_limit: 86400
            #   size_limit: 35000000
            #
            # Together these settings allow for an average throughput of 400
            # events/sec and a backlog of about 24 hours of traffic before
            # events are dropped due to size or age limits.
            {
                'name': 'push_interval',
                'default': 5,
                'comment': 'How often to push events to SSE, in seconds',
            },
            {
                'name': 'batch_limit',
                'default': 2000,
                'comment': 'Maximum number of events to push to SSE per interval',
            },
            {
                'name': 'age_limit',
                'default': 24*3600,
                'comment': 'Maximum queued event age, in seconds (drop older events)',
            },
            {
                'name': 'size_limit',
                'default': 35*1000*1000,
                'comment': 'Maximum queue size, in events (drop oldest events)',
            },
            {
                'name': 'vacuum_interval',
                'default': 24*3600,
                'comment': 'How often to vacuum queue DB, in seconds',
            },
            {
                'name': 'vacuum_limit',
                'default': 350000,
                'comment': 'Maximum queue size when vacuuming queue DB, in entries',
            },
            {
                'name': 'forward',
                'default': [],
                'comment': 'Additional salt returners to send events to when flushing the queue',
            },
        ),
    },
    {
        'name': 'sseapi_rpc_queue',
        'comment': 'Queue some RPC calls locally and send to SSE in batches',
        'default': (
            {
                'name': 'name',
                'default': 'sseapi-rpc',
                'comment': 'RPC queue name',
            },
            {
                'name': 'strategy',
                'default': 'never',
                'comment': 'When to queue RPC calls: always, on_failure, never',
            },
            # Queue defaults should be set together, e.g.:
            #
            #   push_interval: 5
            #   batch_limit: 500
            #   age_limit: 3600
            #   size_limit: 360000
            #
            # Together these settings allow for an average throughput of 100
            # calls/sec and a backlog of about an hour of traffic before calls
            # are dropped due to size or age limits.
            {
                'name': 'push_interval',
                'default': 5,
                'comment': 'How often to send calls to SSE, in seconds',
            },
            {
                'name': 'batch_limit',
                'default': 500,
                'comment': 'Maximum number of calls to push to SSE per interval',
            },
            {
                'name': 'age_limit',
                'default': 3600,
                'comment': 'Maximum queued call age, in seconds (drop older entries)',
            },
            {
                'name': 'size_limit',
                'default': 360000,
                'comment': 'Maximum queue size, in entries (drop oldest entries)',
            },
            {
                'name': 'vacuum_interval',
                'default': 24*3600,
                'comment': 'How often to vacuum queue DB, in seconds',
            },
            {
                'name': 'vacuum_limit',
                'default': 100000,
                'comment': 'Maximum queue size when vacuuming queue DB, in entries',
            },
        ),
    },
    {
        'name': 'sseapi_local_cache',
        'comment': 'Cache some SSE objects locally',
        'default': (
            {
                'name': 'load',
                'default': '3600',
                'comment': 'Cache lifetime for save_load() payloads, in seconds',
            },
            {
                'name': 'tgt',
                'default': '300',
                'comment': 'Cache lifetime for SSE target group, in seconds',
            },
        ),
    },
    {
        'name': 'sseapi_command_age_limit',
        'default': 0,
        'comment': 'Maximum age of a command, in seconds (drop older entries). Default is 0 which disables the feature.'
    },
)


def mkdict(opts, opts_list):
    for item in opts_list:
        if isinstance(item['default'], (list, tuple)) and item['default']:
            opts[item['name']] = {}
            mkdict(opts[item['name']], item['default'])
        else:
            opts[item['name']] = item


SSEAPE_OPTS_DICT = {}

mkdict(SSEAPE_OPTS_DICT, SSEAPE_OPTS)


def _get_opt(opts, key):
    '''
    Get an option from a dict. The key can be a single name or a dot-delimited
    hierarchical name to get a nested option.
    '''
    if '.' in key:
        keys = key.split('.')
        leaf = opts
        try:
            for k in keys:
                leaf = leaf[k]
            return leaf
        except KeyError:
            pass
    return opts.get(key)


def get_default(master_opts, key):
    '''
    Get an SSEAPE configuration default value
    '''
    val = None
    sseape_opt = _get_opt(SSEAPE_OPTS_DICT, key)
    if sseape_opt:
        val = sseape_opt['default']
        if callable(val):
            val = val(master_opts)
    return val


def get(master_opts, key):
    '''
    Get an SSEAPE configuration value
    '''
    val = None
    sseape_opt = _get_opt(SSEAPE_OPTS_DICT, key)
    if sseape_opt:
        val = _get_opt(master_opts, key)
        if val is None:
            val = get_default(master_opts, key)
        if 'tweak' in sseape_opt:
            val = sseape_opt['tweak'](val)
    return val


def generate(ext_modules=False,
             default_config=False,
             returner='sseapi',
             fs_update_interval=60,
             timeout=15):
    '''
    Get default configuration suitable for writing to a config file
    '''
    if default_config is False and ext_modules is False:
        default_config = True

    master_opts = salt.config.master_config(os.path.join(salt.syspaths.CONFIG_DIR, 'master'))
    config = io.StringIO()
    if ext_modules:
        fields = {}
        for entry in dir(sseape.loader):
            if not entry.endswith('_dirs'):
                continue
            fields[entry] = yaml.dump(
                {entry: list(getattr(sseape.loader, entry)())},
                default_flow_style=False,
                indent=2,
                line_break=None
            ).strip()
        config.write(to_unicode(EXT_DIRS_TEMPLATE.format(**fields)))

    def write_defaults(opts, indent=0):
        for item in opts:
            if item.get('hidden'):
                continue
            if isinstance(item['default'], (list, tuple)) and item['default']:
                config.write(to_unicode('\n'))
                if item.get('comment'):
                    config.write(to_unicode('{}# {}\n'.format(indent * ' ', item['comment'])))
                config.write(to_unicode('#{}{}:\n'.format(indent * ' ', item['name'])))
                write_defaults(item['default'], indent + 2)
                config.write(to_unicode('\n'))
            else:
                default = item['default']
                if callable(default):
                    default = default(master_opts)
                line = '#{}{}: {}'.format(indent * ' ', item['name'], '' if default is None else default)
                if item.get('comment'):
                    line += (42 - len(line)) * ' '
                    line += '  # {}'.format(item['comment'])
                config.write(to_unicode(line + '\n'))

    if default_config:
        fields = {
            'returner': returner,
            'returner_config': SSE_PGJSONB_CONFIG if returner == 'sse_pgjsonb' else '',
            'fs_update_interval': fs_update_interval,
            'timeout': timeout,
        }
        config.write(to_unicode(CONFIG_TEMPLATE.format(**fields)))
        write_defaults(SSEAPE_OPTS)

    return to_str(config.getvalue())
