# -*- coding: utf-8 -*-
'''
The RAAS management engine

Query the db for commands and run them!
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
import bisect
import copy
import datetime
import hashlib
import json
import logging
import multiprocessing
import os
import signal
import threading
import time
import uuid

# Import 3rd-party libs
from sseapiclient.exc import NotConnectable

# Import Salt libs
import salt.client
import salt.config
import salt.ext.six as six
import salt.fileclient
import salt.key
import salt.runner
import salt.syspaths
import salt.utils.args
import salt.utils.event
import salt.wheel

# Import SSEAPE libs
import sseape.utils.compat as compat
import sseape.utils.config as sseape_config
import sseape.utils.json
from sseape.utils.client import make_api_client
from sseape.utils.decorators import skip_if_unchanged

__virtualname__ = 'sseapi'
log = logging.getLogger(__name__)

REFRESH_MISSING_GRAINS_INTERVAL = 60  # minutes

METRIC_COMMANDS_PROCESSED = 'raas_master_commands_processed'
METRIC_MASTER_GRAINS_PUSHED = 'raas_master_master_grains_pushed'
METRIC_MINION_KEYS_PUSHED = 'raas_master_minion_keys_pushed'
METRIC_MINION_CACHES_PUSHED = 'raas_master_minion_cache_pushed'
METRIC_MASTERFS_PUSHED = 'raas_master_masterfs_pushed'
METRIC_ENGINE_ITERATION_TIME = 'raas_master_sseapi_engine_iteration_seconds'

EMPTY_METRICS = {
    METRIC_COMMANDS_PROCESSED: 0,
    METRIC_MASTER_GRAINS_PUSHED: 0,
    METRIC_MINION_KEYS_PUSHED: 0,
    METRIC_MINION_CACHES_PUSHED: 0,
    METRIC_MASTERFS_PUSHED: 0,
    METRIC_ENGINE_ITERATION_TIME: 0,
}


def __virtual__():
    if '__role' not in __opts__:
        return False, 'Unable to find out the role(master or minion)'
    if __opts__['__role'] != 'master':
        return (False,
                'The SSEApi engine is meant to run on the salt-master, '
                'not on {0}'.format(__opts__['__role']))
    return True


class SSEApiEngine(object):

    def __init__(self, opts=None):
        if opts is None:
            opts = salt.config.master_config(os.path.join(salt.syspaths.CONFIG_DIR, 'master'))
        try:
            # ignore sseapi fileserver backend updates to raas since it is
            # already known to raas ( raas_master issue #91 )
            #
            self.orig_opts = opts
            fb_copy = opts['fileserver_backend'][:]
            fb_copy.remove('sseapi')
            opts_shallow_copy = opts.copy()
            opts_shallow_copy['fileserver_backend'] = fb_copy
            self.opts = opts_shallow_copy
        except (KeyError, ValueError):
            # No sseapi file backend is configured so nothing needs to be ignored
            #
            self.opts = opts

        self._raas_client = None
        self.master_id = self.opts['id']
        self.cluster_id = self.opts.get('sseapi_cluster_id')
        self.failover_alias = self._get_failover_uuid()
        self.client = salt.client.get_local_client(mopts=self.opts)
        minion_opts = salt.config.minion_config(
            os.path.join(
                self.opts.get('config_dir', salt.syspaths.CONFIG_DIR),
                'minion'))
        minion_opts['file_client'] = 'local'
        minion_opts['pillar'] = minion_opts.get('pillar', {})
        self.caller = salt.client.Caller(mopts=minion_opts)
        self.wheel = salt.wheel.WheelClient(self.opts)
        self.key = salt.key.Key(self.opts)
        self.cache = salt.cache.factory(self.opts)
        self.fsclient = salt.fileclient.FSClient(self.opts)
        self.fmap = {'local': self._local,
                     'runner': self._runner,
                     'wheel': self._wheel}
        self.minion_key_state = None
        self.minion_cache = None
        self.minion_cache_hashes = {}
        self.__last_pushed_minion = None
        self.__last_grains_refresh = None
        self.__sseapi_last_auth_timestamp = None
        self.master_cache = None
        self.master_fs = None
        # Wire up our own handler to handle signals when children processes
        # complete.
        signal.signal(signal.SIGCHLD, self._signal_handler)

    @property
    def raas_client(self):
        if self._raas_client is None:
            self._raas_client = make_api_client(self.opts)
        return self._raas_client

    def _get_failover_uuid(self):
        '''
        Get the failover master alias
        '''
        if self.opts.get('sseapi_failover_master'):
            fn_ = os.path.join(self.opts['cachedir'], '.sseapi_failover_uuid')
            if not os.path.exists(fn_):
                uid = uuid.uuid4().hex
                with compat.fopen(fn_, 'wb+') as fp_:
                    fp_.write(uid.encode())
                return uid
            with compat.fopen(fn_, 'rb') as fp_:
                return fp_.read().decode()
        return None

    def _signal_handler(self, signum, frame):
        '''
        Clean up all completed child processes
        '''
        # TODO: Decide if this should be called when every child process
        #       terminates, or once per Master CMD polling iteration.
        log.debug('Cleaning up completed multiprocess.Process.')
        log.trace('Calling multiprocessing.active_children()')
        multiprocessing.active_children()  # pylint: disable=not-callable

    def _run_runner(self, cmd):
        '''
        Execute the runner in a new process. `runner` creates the new process
        and runs this function within that process.
        DO NOT CREATE A NEW PROCESS! We do not want to nest processes.
        '''
        r_client = salt.runner.Runner(self.orig_opts)
        log.debug('Runner command: %s', json.dumps(cmd))
        low = cmd['low']
        # Expect cmd['low']['arg'] == {'arg': [...], 'kwarg': {...}}. Extract
        # positional and keyword args and remove empty keyword args.
        quasi_args = cmd['low'].get('arg', {}).get('arg', [])
        parsed_args, parsed_kwargs = salt.utils.args.parse_input(quasi_args, condition=False)
        low['kwargs'] = cmd['low'].get('arg', {}).get('kwarg', {})
        low['args'] = parsed_args
        # Insert the sub-key for orchestrations
        if low['fun'] in ['state.orchestrate', 'state.orch', 'state.sls']:
            # Not sure of ramifications of this yet, wrap in try/except to
            # prevent engine from crashing unexpectedly
            try:
                if 'mods' in low['kwargs']:
                    low['kwargs']['orchestration_jid'] = cmd['jid']
            except KeyError as exc:
                log.debug('Error when attempting to massage dict for orch runner call: %s', str(exc))

        # merge the quasi_args with the kwargs...
        low['kwargs'].update(parsed_kwargs)

        # Stop passing 'args' and 'kwargs', it has been deprecated and removed in Salt Oxygen
        low['arg'] = low.pop('args')
        low['kwarg'] = low.pop('kwargs')

        log.debug('Runner command low: %s', json.dumps(low))
        # Running asynchronously. Results of this execution may be collected by
        # attaching to the master event bus or by examing the master job cache.

        # Taken from the 'async' mixin function. We do not want to use the
        # async function, because we are already running in a
        # multiprocess.Process created by RaaS.
        #
        # Be sure to use the existing jid. Pass the existing jid in to ensure
        # that _gen_async_pub does not create one.
        user = cmd.get('user', None) or low.get('user', None) or 'UNKNOWN'
        async_pub = r_client._gen_async_pub(jid=cmd['jid'])

        r_client._proc_function(low['fun'],
                                low,
                                user,
                                async_pub['tag'],
                                async_pub['jid'],
                                daemonize=False)

    def _local(self, cmd):
        # Expect cmd['low']['arg'] == {'arg': [...], 'kwarg': {...}}. Extract
        # positional and keyword args and remove empty keyword args.
        arg = cmd['low'].get('arg', {}).get('arg', [])
        kwarg = cmd['low'].get('arg', {}).get('kwarg', {})
        # Dict comprehensions are not python 2.6 compatible
        #kwarg = {key: value for key, value in kwarg.items() if value}
        for key, value in kwarg.copy().items():
            if not value:
                kwarg.pop(key)
        kwargs = {
            'tgt': cmd['low']['tgt'],
            'fun': cmd['low']['fun'],
            'arg': arg,
            'kwarg': kwarg,
            'tgt_type': cmd['low']['tgt_type'],
            'jid': cmd['jid'],
        }
        ret = self.client.cmd_async(**kwargs)
        if ret == 0:
            data = {'returned': [],
                    'missing': [],
                    'fun': cmd['low']['fun'],
                    'arg': arg}
            salt.utils.event.get_master_event(__opts__,
                                              __opts__['sock_dir']).fire_event(
                data=data, tag='salt/job/{}/complete'.format(cmd['jid']))
        return ret

    def _runner(self, cmd):
        '''
        Execute the runner in a new process, I know we are nesting processes,
        but lets make this all work first.
        '''
        # TODO: We should switch this over to execute the runner within the master
        # via the runner's async operation. We can do this once we can ingest the
        # Runner returns off the event bus, or to use a thread pool executor
        thread = threading.Thread(target=self._run_runner, args=[cmd])
        thread.start()

    def _wheel(self, cmd):
        ret = {}
        jid = cmd['jid']
        ret['jid'] = jid
        ret['id'] = self.master_id
        fun = cmd['low']['fun']
        ret['fun'] = fun

        if fun in self.wheel.functions:
            try:
                args = cmd['low']['arg']
            except KeyError:
                # Makes 'arg' optional
                args = {}

            try:
                if isinstance(args, dict):
                    # Expect cmd['low']['arg'] == {'arg': [...], 'kwarg': {...}}. Extract
                    # positional and keyword args and remove empty keyword args.
                    quasi_args = cmd['low'].get('arg', {}).get('arg', [])
                    parsed_args, parsed_kwargs = salt.utils.args.parse_input(quasi_args, condition=False)
                    kwargs = cmd['low'].get('arg', {}).get('kwarg', {})
                    kwargs.update(parsed_kwargs)
                    ret['return'] = self.wheel.functions[fun](*parsed_args, **kwargs)
                    ret['success'] = True
                else:
                    msg = ('Wheel functions expect args to be passed as a dictionary.')
                    ret['return'] = msg
                    ret['success'] = False
            except Exception as exc:  # pylint: disable=broad-except
                ret['return'] = str(exc)
                ret['success'] = False
        else:
            ret['return'] = '{0} is not a supported wheel function.'.format(fun)
            ret['success'] = False

        try:
            self.raas_client.api.ret.save_return(master_id=self.master_id, payload=ret)
        except NotConnectable as exc:
            log.error('Failed to send return to SSE for jid %s: %s', ret['jid'], str(exc))
        return jid

    def _get_master_data_cache(self):
        '''
        Return the master data cache.
        '''
        log.info('Updating master data cache')
        return {
            'cluster_id': self.cluster_id,
            'grains': self.caller.sminion.opts['grains']
        }

    def _sanitize_bytes(self, data):
        '''
        Walk though a JSON-compatible data structure, replacing non-utf-8
        sequences in strings so they can be serialized to json. Ideally we
        would just replace these sequences during serialization by overriding
        Python's json string encoding, but the module doesn't allow for that.
        '''
        def neq(a, b):
            '''
            Avoid unicode warnings by checking types first
            '''
            return type(a) != type(b) or a != b  # pylint: disable=unidiomatic-typecheck

        if isinstance(data, dict):
            for (key, value) in data.items():
                key2 = self._sanitize_bytes(key)
                value2 = self._sanitize_bytes(value)
                if neq(key2, key):
                    data.pop(key)
                    data[key2] = value2
                elif neq(value2, value):
                    data[key] = value2
            return data
        if isinstance(data, list):
            for (idx, item) in enumerate(data):
                item2 = self._sanitize_bytes(item)
                if neq(item2, item):
                    data[idx] = item2
            return data
        if isinstance(data, six.binary_type):
            try:
                data = data.decode('utf-8')
            except UnicodeDecodeError:
                data = data.decode('utf-8', errors='replace')
            # continue now that data is a string
        if isinstance(data, six.string_types):
            # Remove null characters from strings
            data = data.replace('\x00', '')
        return data

    def _get_minion_data_cache(self):
        '''
        Return the minion data cache
        '''
        log.info('Updating minion data cache')
        ret = []
        if self.opts.get('minion_data_cache'):
            epoch = datetime.datetime.utcfromtimestamp(0)
            now = (datetime.datetime.utcnow() - epoch).total_seconds()
            minions = self.cache.list('minions')
            for minion in minions:
                miniondata = {}
                bank = 'minions/{}'.format(minion)
                # Include a timestamp from the minion cache. Raas uses this to
                # report the most recent minion grains in multi-master configs.
                mtime = self.cache.updated(bank, 'data')
                miniondata['mtime'] = int(mtime or now)

                mdata = self.cache.fetch(bank, 'data')
                if 'pillar' in mdata and self.opts.get('sseapi_cache_pillar', False):
                    miniondata['pillar'] = mdata['pillar']
                if 'grains' in mdata:
                    miniondata['grains'] = self._sanitize_bytes(mdata['grains'])
                else:
                    log.debug('No grains found for minion %s', minion)
                    continue
                ret.append({minion: miniondata})
        return ret or None

    def _get_minion_key_state(self):
        '''
        Gather minion key state
        '''
        log.info('Updating minion key state cache')
        return self.key.list_keys()

    def _get_master_fs(self):
        '''
        Gather the information about the fileserver data and send up to RAAS
        '''
        log.info('Updating masterfs cache')
        envs = self.fsclient.envs()
        ret = {}
        for env in envs:
            ret[env] = self.fsclient.file_list(env)
        return ret

    def _process_cmds(self):
        '''
        Query the SSEApi server for commands
        '''
        log.info('Retrieving commands from SSE')
        try:
            cmds = self.raas_client.api.cmd.get_master_cmd(
                    self.cluster_id or self.master_id,
                    self.failover_alias).ret
        except NotConnectable as exc:
            log.error('Failed to retrieve commands from SSE: %s', str(exc))
            return

        log.info('Commands: %s', cmds)
        for cmd in cmds:
            try:
                if self.skip_expired_cmds(cmd):
                    continue
                log.info('Running %s(%r)', cmd['cmd'], cmd)
                jid = self.fmap[cmd['cmd']](cmd)
                if cmd['cmd'] != 'local':
                    # Currently we don't need to get the jid here, but if we
                    # need it in the future, this is how to get it for runner
                    # and wheel commands.
                    jid = cmd['jid']
                self.iteration_metrics[METRIC_COMMANDS_PROCESSED] += 1
            except AttributeError:
                pass  # TODO: More elegant fail needed

    def skip_expired_cmds(self, cmd):
        ret = False
        if cmd.get('jid'):
            command_age = (datetime.datetime.utcnow() -
                           datetime.datetime.strptime(cmd['jid'], '%Y%m%d%H%M%S%f')).total_seconds()
            allowed_age = int(self.opts.get('sseapi_command_age_limit', 0))
            if allowed_age and command_age > allowed_age:
                log.warning('Command age - %s, Allowed age - %s, JID - %s has expired. Marking it as complete.',
                            command_age, allowed_age, cmd['jid'])
                salt.utils.event.get_master_event(
                    __opts__,
                    __opts__['sock_dir']).fire_event(
                        data={},
                        tag='salt/job/{}/complete'.format(cmd['jid']))
                ret = True
        return ret

    def _update_caches(self):
        self.master_cache = self._get_master_data_cache()
        self.minion_cache = self._get_minion_data_cache()
        self.minion_key_state = self._get_minion_key_state()
        self.master_fs = self._get_master_fs()

    def _refresh_missing_grains(self):
        '''
        Force a grains refresh on accepted minions with no cached grains.
        '''
        # If the engine has just started (and thus the master has just
        # started), give minions time to connect instead of immediately
        # hammering them with a grains refresh.
        now = datetime.datetime.utcnow()
        if self.__last_grains_refresh is None:
            self.__last_grains_refresh = now

        # If we have no cached grains, don't bother trying to refresh
        if self.minion_cache is None:
            return

        # If the interval has expired, send the refresh_grains command
        if now > self.__last_grains_refresh + datetime.timedelta(minutes=REFRESH_MISSING_GRAINS_INTERVAL):
            cached = set()
            for m in self.minion_cache:  # pylint: disable=not-an-iterable
                cached.add(next(iter(m)))
            needs_refresh = []
            for minion in self.minion_key_state['minions']:
                if minion not in cached:
                    needs_refresh.append(minion)
            if needs_refresh:
                log.info('Refreshing grains on %d accepted minions missing from cache', len(needs_refresh))
                self.client.cmd_async(
                    tgt_type='list',
                    tgt=','.join(needs_refresh),
                    fun='saltutil.refresh_grains')
            else:
                log.info('No accepted minions missing from cache')
            self.__last_grains_refresh = now

    def _get_minion_cache_hashes(self, minions):
        '''
        Get a hash of each minion's grains
        '''
        hashes = {}
        for m in minions:
            # only need a shallow copy, not changing deep keys
            hashable = copy.copy(minions[m])
            hashable.pop('mtime')
            hashable = json.dumps(hashable,
                                  cls=sseape.utils.json.JSONEncoder,
                                  sort_keys=True).encode('utf-8')
            hashes[m] = hashlib.sha256(hashable).hexdigest()
        return hashes

    @skip_if_unchanged('master_cache', magic='sseapi_auth_timestamp')
    def _push_master_cache(self):
        '''
        Push an update of the contents of the master data cache up to SSEApi
        '''
        log.info('Sending master cache to SSE')
        try:
            ret = self.raas_client.api.master.save_master(
                    master_id=self.master_id,
                    cluster_id=self.master_cache['cluster_id'],
                    grains=self.master_cache['grains']).ret
            self.iteration_metrics[METRIC_MASTER_GRAINS_PUSHED] += 1
            return ret
        except NotConnectable as exc:
            log.error('Failed to send master cache to SSE: %s', str(exc))
            return False

    @skip_if_unchanged('minion_key_state', magic='sseapi_auth_timestamp')
    def _push_minion_key_state(self):
        '''
        Push minion key state information to SSEApi
        '''
        log.info('Sending minion key state to SSE')
        try:
            ret = self.raas_client.api.minions.save_minion_key_state(
                    master_id=self.master_id,
                    keys=self.minion_key_state).ret
            keys_total = sum(len(self.minion_key_state[k]) for k in self.minion_key_state)
            self.iteration_metrics[METRIC_MINION_KEYS_PUSHED] += keys_total
            return ret
        except NotConnectable as exc:
            log.error('Failed to send minion key state to SSE: %s', str(exc))
            return False

    def __get_updated_minions_subset(self, new_hashes):
        '''
        Get a list of updated minions that is no longer than the configured
        maximum minion grains payload.
        '''
        updated = sorted([m for m in new_hashes if new_hashes[m] != self.minion_cache_hashes.get(m)])

        # Start the list of updated minions where the previous iteration left
        # off so that, in pathological cases where grains are changing
        # frequently, we are not always sending up the same subset of minions.
        if self.__last_pushed_minion:
            start = bisect.bisect_right(updated, self.__last_pushed_minion)
        else:
            start = 0
        updated = updated[start:] + updated[:start]

        # Truncate the list to the configured maximum
        max_payload = sseape_config.get(self.opts, 'sseapi_max_minion_grains_payload')
        del updated[max_payload:]

        # Remember where to start the list next iteration
        self.__last_pushed_minion = updated[-1] if updated else None

        return updated

    def _push_minion_cache(self):
        '''
        Push an update of the contents of the minion data cache up to SSEApi
        '''
        # If the engine has re-authenticated to raas since the last iteration,
        # discard the minion cache hashes, since we can't know what minion
        # cache data raas has.
        if self.sseapi_auth_timestamp != self.__sseapi_last_auth_timestamp:
            self.minion_cache_hashes = {}
            self.__sseapi_last_auth_timestamp = self.sseapi_auth_timestamp

        minions = {}
        if self.minion_cache:
            for minion in self.minion_cache:  # pylint: disable=not-an-iterable
                if not minion:
                    break
                minions.update(minion)

        # Identify deleted and updated minions and send data that has changed,
        # subject to the configured minion grains payload size limit.
        new_hashes = self._get_minion_cache_hashes(minions)
        deleted = list(set(self.minion_cache_hashes) - set(new_hashes))
        updated = self.__get_updated_minions_subset(new_hashes)
        if deleted or updated:
            update_dict = {}
            for m in updated:
                update_dict[m] = minions[m]
            minions_delta = {
                'delete': deleted,
                'update': update_dict
            }
            log.info('Sending minion cache delta to SSE (%s updated, %s deleted)',
                    len(updated), len(deleted))
            try:
                self.raas_client.api.minions.save_minion_cache(
                        master_id=self.master_id,
                        minions_delta=minions_delta)
                for m in deleted:
                    self.minion_cache_hashes.pop(m)
                for m in updated:
                    self.minion_cache_hashes[m] = new_hashes[m]
                self.iteration_metrics[METRIC_MINION_CACHES_PUSHED] += len(deleted) + len(updated)
            except NotConnectable as exc:
                log.error('Failed to send minion cache to SSE: %s', str(exc))
                self.minion_cache_hashes = {}
        else:
            log.info('No minion grains changes detected')

    @skip_if_unchanged('master_fs', magic='sseapi_auth_timestamp')
    def _push_master_fs(self):
        '''
        Send master fileserver data to RAAS
        '''
        log.info('Sending masterfs cache to SSE')
        try:
            ret = self.raas_client.api.masterfs.save_masterfs(self.master_id, self.master_fs).ret
            masterfs_total = sum(len(self.master_fs[k]) for k in self.master_fs)
            self.iteration_metrics[METRIC_MASTERFS_PUSHED] += masterfs_total
            return ret
        except NotConnectable as exc:
            log.error('Failed to send master fileserver data to SSE: %s', str(exc))
            return False

    def _send_iteration_complete_event(self, duration):
        '''
        Fire an event marking the end of the engine iteration. There are two
        purposes for this. First, it reports engine metrics to raas. Second, it
        ensures that there is at least one event on the bus every poll_interval
        seconds, which helps the salt-master event batch process because we
        will be guaranteed to process the event queue (set by event_return_queue
        (max events before flushing) and event_return_queue_max_seconds (age of
        oldest item in queue before we flush)).
        '''
        event = salt.utils.event.get_master_event(__opts__, __opts__['sock_dir'])
        event.fire_event(data={'metrics': self.iteration_metrics}, tag='salt/raas_master/iteration')

    @property
    def sseapi_auth_timestamp(self):
        return self.raas_client.last_auth_request_time

    def start(self):
        interval = self.opts.get('sseapi_poll_interval', 30)
        while True:
            self.iteration_metrics = EMPTY_METRICS.copy()
            start = time.time()
            log.info('Start RaaS engine polling iteration...')
            try:
                self._process_cmds()
                self._update_caches()
                self._refresh_missing_grains()
                self._push_master_cache()
                self._push_minion_key_state()
                self._push_minion_cache()
                self._push_master_fs()
            except Exception as exc:  # pylint: disable=broad-except
                log.info('RaaS engine iteration interrupted with exception: %s', exc)
            end = time.time()
            duration = end - start
            self.iteration_metrics[METRIC_ENGINE_ITERATION_TIME] += duration
            self._send_iteration_complete_event(duration)
            stime = interval - duration
            if stime < 0:
                # Give us some time anyway
                stime = interval / 5
            log.info('End RaaS engine polling iteration, sleeping %s', stime)
            time.sleep(stime)


def start():
    '''
    Loop over the reactor engine
    '''
    if '__opts__' in globals():
        opts = __opts__
    else:
        opts = None

    rengine = SSEApiEngine(opts)
    rengine.start()
