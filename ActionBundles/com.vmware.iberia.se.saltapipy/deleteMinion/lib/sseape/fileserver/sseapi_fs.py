# -*- coding: utf-8 -*-

# Copyright (C) 2020 SaltStack, Inc.
#
# This file is licensed only for use with SaltStack's Enterprise software
# product and may not be used for any other purpose without prior written
# authorization from SaltStack, Inc.  The license terms governing your use of
# Salt Stack Enterprise also govern your use of this file. See license terms at
# https://www.saltstack.com/terms/

# Import Python libs
from __future__ import absolute_import
import errno
import logging
import os
import tempfile
import time

HAS_PATHLIB = False
try:
    import pathlib
    HAS_PATHLIB = True
except ImportError:
    HAS_PATHLIB = False

# Import 3rd-party libs
from sseapiclient.exc import NotConnectable, RPCError

# Import Salt libs
import salt.ext.six as six
import salt.fileserver
import salt.utils.gzip_util

# Import SSEAPE libs
import sseape.utils.compat as compat
from sseape.utils.client import make_api_client

if compat.is_fcntl_available():
    import fcntl

log = logging.getLogger(__name__)

__virtualname__ = 'sseapi'


def __virtual__():
    if '__role' not in __opts__:
        return False, 'Unable to find out the role(master or minion)'
    if __opts__['__role'] != 'master':
        return (False,
                'The SSEApi fs is meant to run on the salt-master, '
                'not on {0}'.format(__opts__['__role']))
    return True


def get_client():
    if 'sseapi_client' not in __context__:
        __context__['sseapi_client'] = make_api_client(__opts__)
    return __context__['sseapi_client']


def find_file(path, saltenv='base', **kwargs):
    '''
    Search the environment for the relative path
    '''
    fnd = {'path': None}
    if 'env' in kwargs:
        # "env" is not supported; use "saltenv"
        kwargs.pop('env')

    rel_path = path = os.path.normpath(path)
    if not path.startswith('/'):
        # Raas requires the / root to always be passed
        path = '/' + path
    try:
        cache_state = file_hash({'saltenv': saltenv, 'path': path},
                                {'rel': path, 'path': path})
        if 'hsum' in cache_state:
            fnd.update({'path': cache_state['path'], 'rel': rel_path})
            return fnd
        fdat = get_client().api.fs.get_file(saltenv=saltenv, path=path).ret
        tmp = os.path.join(_cache_root(), saltenv, 'content/')
        if not os.path.isdir(tmp):
            try:
                os.makedirs(tmp)
            except OSError as exc:
                # Race condition when creating directory?
                if exc.errno != errno.EEXIST:
                    raise

        fd_, tmp = tempfile.mkstemp(dir=tmp, prefix='file_')
        os.close(fd_)
        with compat.fopen(tmp, 'wb+') as fp_:
            if six.PY3 and isinstance(fdat['contents'], str):
                fp_.write(fdat['contents'].encode('utf-8'))

            else:
                fp_.write(fdat['contents'])

        fnd.update({'path': tmp, 'rel': rel_path})
    except (NotConnectable, RPCError) as exc:
        log.debug('Failed to get file(path: %s; saltenv: %s): %s', path, saltenv, str(exc))
    return fnd


def envs():
    '''
    Return the file server environments
    '''
    ret = []
    try:
        envs = get_client().api.fs.get_envs().ret
        for env in envs:
            if six.PY2:
                env = env.decode('utf-8')
            ret.append(env)
    except (NotConnectable, RPCError) as exc:
        log.error('Failed to get the salt environments: %s', str(exc))
    return ret


def serve_file(load, fnd):
    '''
    Return a chunk from a file based on the data received
    '''
    if 'env' in load:
        # "env" is not supported; use "saltenv"
        load.pop('env')

    ret = {'data': '',
           'dest': ''}
    if 'path' not in load or 'loc' not in load or 'saltenv' not in load:
        return ret
    if not fnd['path']:
        return ret
    fpath = os.path.normpath(fnd['path'])
    if not os.path.exists(fpath):
        return ret
    ret['dest'] = fnd['rel']
    gzip = load.get('gzip', None)
    with compat.fopen(fpath, 'rb') as fp_:
        fp_.seek(load['loc'])
        data = fp_.read()
        if gzip and data:
            data = salt.utils.gzip_util.compress(data, gzip)
            ret['gzip'] = gzip
        ret['data'] = data
    return ret


def _cache_root():
    return os.path.join(__opts__['cachedir'], __virtualname__)


def file_hash(load, fnd):
    '''
    Return a file hash, the hash type is set in the master config file
    '''
    if 'env' in load:
        # "env" is not supported; use "saltenv"
        load.pop('env')

    if 'path' not in load or 'saltenv' not in load:
        return ''
    path = fnd['path']

    # Set the hash_type as configured
    ret = {'hash_type': __opts__['hash_type']}

    # Check if the hash is cached
    cache_path = os.path.join(_cache_root(),
                              load['saltenv'],
                              'hash',
                              '{0}.hash.{1}'.format(fnd['rel'].lstrip('/'),
                              __opts__['hash_type']))
    if os.path.exists(cache_path):
        try:
            with compat.fopen(cache_path, 'r') as fp_:
                try:
                    hsum, mtime, cache_content = fp_.read().split(':')
                except ValueError:
                    log.debug('Fileserver attempted to read incomplete cache file. Retrying.')
                    # Delete the file since its incomplete (either corrupted or incomplete)
                    try:
                        os.unlink(cache_path)
                    except OSError:
                        pass
                    return file_hash(load, fnd)
                # We have a cached hash so return that
                ret['hsum'] = hsum
                ret['path'] = cache_content
                return ret
        except (os.error, IOError):  # Can't use Python select() because we need Windows support
            log.debug('Fileserver encountered lock when reading cache file. Retrying.')
            # Delete the file since its incomplete (either corrupted or incomplete)
            try:
                os.unlink(cache_path)
            except OSError:
                pass
            return file_hash(load, fnd)

    # If file contents are not cached from SSE, there's nothing to hash
    if not path.startswith(_cache_root()):
        return {}

    # Create the cache directory if necessary
    cache_dir = os.path.dirname(cache_path)
    if not os.path.exists(cache_dir):
        try:
            os.makedirs(cache_dir)
        except OSError as exc:
            # Race condition when creating directory?
            if exc.errno != errno.EEXIST:
                raise

    # Save the cache object: "hash:mtime:content_path"
    ret['hsum'] = compat.get_hash(path, __opts__['hash_type'])
    ret['path'] = path
    cache_object = '{0}:{1}:{2}'.format(ret['hsum'], os.path.getmtime(path), path)
    try:
        with compat.flopen(cache_path, 'w') as fp_:
            fp_.write(cache_object)
    except AttributeError:
        # We just do what flopen does
        with compat.fopen(cache_path, 'w') as fp_:
            if compat.is_fcntl_available(check_sunos=True):
                fcntl.flock(fp_.fileno(), fcntl.LOCK_SH)
            fp_.write(cache_object)
            if compat.is_fcntl_available(check_sunos=True):
                fcntl.flock(fp_.fileno(), fcntl.LOCK_UN)
    return ret


def _file_lists(saltenv, form):
    '''
    Return a list of files or dirs in a saltenv
    '''
    # Return cached data if it is available
    list_cachedir = os.path.join(__opts__['cachedir'], 'file_lists', __virtualname__)
    if not os.path.isdir(list_cachedir):
        try:
            os.makedirs(list_cachedir)
        except os.error:
            log.critical('Unable to make cachedir %s', list_cachedir)
            return []
    list_cache = os.path.join(list_cachedir, '{0}.p'.format(saltenv))
    w_lock = os.path.join(list_cachedir, '.{0}.w'.format(saltenv))
    cache_match, _, save_cache = salt.fileserver.check_file_list_cache(__opts__, form, list_cache, w_lock)
    if cache_match is not None:
        return cache_match

    # No current cache, so get data from raas
    try:
        files = get_client().api.fs.get_env(saltenv, include_fs_metadata=False).ret
    except (NotConnectable, RPCError) as exc:
        log.error('Failed to get the file listing for saltenv(%s): %s', saltenv, str(exc))
        return []

    ret = {
        'files': set(),
        'dirs': set()
    }
    for fdata in files:
        ret['files'].add(fdata['path'].lstrip('/'))
    for path in ret['files']:
        if '/' in path:
            ret['dirs'].add(os.path.dirname(path))
    ret['files'] = sorted(ret['files'])
    ret['dirs'] = sorted(ret['dirs'])
    if save_cache:
        salt.fileserver.write_file_list_cache(__opts__, ret, list_cache, w_lock)
    return ret[form]


def file_list(load):
    '''
    Return a list of all files on the file server in a specified
    environment
    '''
    return _file_lists(load['saltenv'], 'files')


def file_list_emptydirs(load):
    '''
    Return a list of all empty directories on the master
    '''
    return []


def dir_list(load):
    '''
    Return a list of all directories on the master
    '''
    return _file_lists(load['saltenv'], 'dirs')


def symlink_list(load):
    '''
    Return a dict of all symlinks based on a given path on the Master
    '''
    return {}


def clear_cache():
    errors = []
    try:
        compat.rm_rf(_cache_root())
    except OSError as exc:
        errors.append(
            'Unable to delete {0}: {1}'.format(_cache_root(), exc)
        )
    return errors


def _get_cached_files(root):
    root_len = len(root)
    hash_suffix_len = len('.hash.' + __opts__['hash_type'])
    tree = {}
    for top, _, file_list in os.walk(root):
        for file_name in file_list:
            tree[os.path.join(top, file_name)[root_len:-hash_suffix_len]] = None

    return tree


def update():
    '''
    Remove stale entries from the cache
    '''
    now = time.time()
    expire = __opts__.get('fileserver.sseapi.cache_timeout', 1)
    expire = expire * 60  # convert to seconds
    suffix = '.hash.' + __opts__['hash_type']
    for my_e in envs():
        cache_root = os.path.join(_cache_root(), my_e, 'hash')
        tree = _get_cached_files(cache_root)
        for afile in tree:
            # remove cache entry and contents for files deleted in RaasDB
            cache_path = os.path.join(cache_root, afile[1:] + suffix)
            mtime = os.path.getmtime(cache_path)
            if mtime + expire < now:
                # remove the cache element and content
                try:
                    with compat.fopen(cache_path, 'r') as fp_:
                        _, mtime, content_path = fp_.read().split(':')
                        os.unlink(cache_path)
                        # Delete content_path only when present under cache_root.
                        if (HAS_PATHLIB and pathlib.Path(_cache_root()) in pathlib.Path(content_path).parents) or \
                           (not HAS_PATHLIB and content_path.startswith(_cache_root())):
                            os.unlink(content_path)
                except Exception as exc:  # pylint: disable=broad-except
                    log.error('Fileserver fail to unlink file: %s', exc)

    return
