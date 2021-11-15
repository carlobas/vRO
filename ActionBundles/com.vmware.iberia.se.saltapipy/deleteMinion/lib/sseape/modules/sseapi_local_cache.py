# coding: utf-8
'''
SSE local cache for arbitrary blobs
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
import sqlite3
import time

# Import Salt libs
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

__virtualname__ = 'sseapi_local_cache'

TABLE_NAME = 'cache'
TABLE_DEFINITION = '(id INTEGER PRIMARY KEY, timestamp REAL, key TEXT, value BLOB)'

# Maximum time (milliseconds) to spend retrying to open the database when
# SQLite reports that it is locked.
LOCK_RETRY_LIMIT = 2000

# Default maximum number of entries to allow in the database when running a
# vacuum. If the database contains more entries than this, the vacuum will be
# skipped.
VACUUM_MAX_ENTRIES = 1000

# How often, in seconds, to run a vacuum automatically
VACUUM_INTERVAL = 3600

# Database entry to track the last vacuum time, to ensure that we don't vacuum
# too often.
LAST_VACUUM_KEY = '~last-vacuum~'


def __virtual__():
    # Just need sqlite3, should be good to go
    return __virtualname__


class CacheConn(sqlite3.Connection):
    '''
    Connection wrapper that puts the database file in the right place and adds
    some logging to some methods. Could use Connection.set_trace_callback() for
    logging but that works only in Python 3.
    '''
    def __init__(self, cache, *args, **kwargs):
        self.open = False
        self.cache = cache
        self.dbfile = os.path.join(__opts__['cachedir'], 'sseapi-{}-cache.sqlite3'.format(self.cache))

        if kwargs.pop('create', True) is False:
            # If the caller does not want to create the database file, try to
            # open it, causing an exception to be raised when it does not
            with open(self.dbfile, 'r'):  # pylint: disable=resource-leakage
                pass

        log.debug('cache %s: opening database %s', self.cache, self.dbfile)
        super(CacheConn, self).__init__(self.dbfile, *args, **kwargs)
        self.open = True
        self.execute('pragma journal_mode=wal')
        self.execute('pragma synchronous=normal')

    def __del__(self):
        if self.open:
            log.debug('cache %s: closed database %s', self.cache, self.dbfile)

    def execute(self, sql, *params):
        log.debug('cache %s: sql: %s', self.cache, sql)
        return super(CacheConn, self).execute(sql, *params)

    def executemany(self, sql, *params):
        log.debug('cache %s: sql: %s', self.cache, sql)
        return super(CacheConn, self).executemany(sql, *params)


def _get_conn(cache):
    '''
    Get a connection to a cache database. If the database is locked, retry a
    few times.
    '''
    start = time.time()
    while True:
        try:
            conn = CacheConn(cache)
            script = '''
                CREATE TABLE IF NOT EXISTS {table} {table_def};
                CREATE UNIQUE INDEX IF NOT EXISTS key_idx ON {table} (key);
                CREATE INDEX IF NOT EXISTS timestamp_idx ON {table} (timestamp);'''.format(
                    table=TABLE_NAME, table_def=TABLE_DEFINITION)
            conn.executescript(script)
            return conn
        except sqlite3.OperationalError as exc:
            if 'database is locked' in str(exc):
                remain = LOCK_RETRY_LIMIT - int(1000 * (time.time() - start))
                if remain > 0:
                    log.debug('cache %s: %s: will retry for %d more msec', cache, str(exc), remain)
                    time.sleep(0.1)
                    continue
            raise


def _get_cache_age_limit(cache):
    '''
    Get the age limit for a cache. Age limits are configured in seconds, for
    example:

    sseapi_local_cache:
      - load: 3600
      - pillar: 60
      - tgt: 300
    '''
    return __opts__.get('sseapi_local_cache', {}).get(cache, 60)


def _purge_old_items(cache):
    '''
    Remove old items from a cache in order to enforce an age limit.
    '''
    deleted = 0
    age_limit = _get_cache_age_limit(cache)
    old = time.time() - age_limit
    cmd = 'DELETE FROM {table} WHERE timestamp < {old} AND key != "{last_vacuum_key}"'.format(
            table=TABLE_NAME, old=old, last_vacuum_key=LAST_VACUUM_KEY)
    with _get_conn(cache) as conn:
        try:
            deleted = conn.execute(cmd).rowcount
            conn.commit()
        except sqlite3.Error as exc:
            log.error('cache %s: failed to delete old items: %s', cache, str(exc))
            deleted = 0

    if deleted:
        log.info('cache %s: deleted %d items older than %d seconds', cache, deleted, age_limit)
        _maybe_vacuum(cache)

    return deleted


def _update_last_vacuum_time(conn, timestamp):
    '''
    Update the last vacuum time stored in the database
    '''
    cmd = '''INSERT OR REPLACE INTO {table} (timestamp, key, value)
                VALUES (:timestamp, :key, :value)'''.format(table=TABLE_NAME)
    args = {
        'timestamp': timestamp,
        'key': LAST_VACUUM_KEY,
        'value': str(timestamp).encode('utf-8')
    }
    conn.execute(cmd, args)
    conn.commit()


def _maybe_vacuum(cache):
    '''
    Try to run a vacuum if it's been a while
    '''
    query = 'SELECT timestamp FROM {table} WHERE key = "{last_vacuum_key}"'.format(
            table=TABLE_NAME, last_vacuum_key=LAST_VACUUM_KEY)
    try:
        with _get_conn(cache) as conn:
            result = conn.execute(query).fetchone()
        last_vacuum = result[0] if result else 0
        if time.time() > last_vacuum + VACUUM_INTERVAL:
            vacuum(cache)
    except sqlite3.Error as exc:
        log.error('cache %s: failed to get last vacuum time: %s', cache, str(exc))


def set(cache, key, value):
    '''
    Set a value in a cache. The key should be a string and the value should be
    bytes.
    '''
    _purge_old_items(cache)

    cmd = '''INSERT OR REPLACE INTO {table} (timestamp, key, value)
                VALUES (:timestamp, :key, :value)'''.format(table=TABLE_NAME)
    args = {
        'timestamp': time.time(),
        'key': key,
        'value': sqlite3.Binary(value)
    }
    try:
        with _get_conn(cache) as conn:
            try:
                conn.execute(cmd, args)
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                raise
        log.info('cache %s: set item %s', cache, key)
    except sqlite3.Error as exc:
        log.error('cache %s: failed to set item %s: %s', cache, key, str(exc))
        raise CommandExecutionError(str(exc))


def set_many(cache, items):
    '''
    Set many values in a cache. The items parameter should be a sequence of
    (key, value) tuples with keys as strings values as bytes.
    '''
    _purge_old_items(cache)

    cmd = '''INSERT OR REPLACE INTO {table} (timestamp, key, value)
                VALUES (:timestamp, :key, :value)'''.format(table=TABLE_NAME)
    timestamp = time.time()
    args = [{'timestamp': timestamp,
             'key': x[0],
             'value': sqlite3.Binary(x[1])} for x in items]
    try:
        with _get_conn(cache) as conn:
            try:
                conn.executemany(cmd, args)
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                raise
        log.info('cache %s: set %d items', cache, len(items))
    except sqlite3.Error as exc:
        log.error('cache %s: failed to set %d items: %s', cache, len(items), str(exc))
        raise CommandExecutionError(str(exc))


def get(cache, key, keypat=None):
    '''
    Return a value from a cache.
    '''
    _purge_old_items(cache)

    query = 'SELECT value FROM {table} WHERE key = "{key}"'.format(table=TABLE_NAME, key=key)
    try:
        with _get_conn(cache) as conn:
            result = conn.execute(query).fetchone()
        if result:
            log.info('cache %s: got item %s', cache, key)
            result = bytes(result[0])
        else:
            log.info('cache %s: no item %s', cache, key)
        return result
    except sqlite3.Error as exc:
        log.error('cache %s: failed to get item %s: %s', cache, key, str(exc))
        raise CommandExecutionError(str(exc))


def get_many(cache, keypat):
    '''
    Get the values of all keys matching a pattern from a cache. The return
    value is a list of (key, value) tuples.
    '''
    _purge_old_items(cache)

    query = 'SELECT key, value FROM {table} WHERE key LIKE "{keypat}" AND key != "{last_vacuum_key}"'.format(
            table=TABLE_NAME, keypat=keypat, last_vacuum_key=LAST_VACUUM_KEY)
    try:
        with _get_conn(cache) as conn:
            results = conn.execute(query).fetchall()
        if results:
            log.info('cache %s: got %d items matching %s', cache, len(results), keypat)
            results = [(x[0], bytes(x[1])) for x in results]
        else:
            log.info('cache %s: no items matching %s', cache, keypat)
        return results
    except sqlite3.Error as exc:
        log.error('cache %s: failed to get items matching %s: %s', cache, keypat, str(exc))
        raise CommandExecutionError(str(exc))


def flush(cache):
    '''
    Flush all the entries from a cache.
    '''
    cmd = 'DELETE FROM {table}'.format(table=TABLE_NAME)
    try:
        with _get_conn(cache) as conn:
            try:
                result = conn.execute(cmd)
                conn.commit()
                log.info('cache %s: flushed %d items', cache, result.rowcount)
            except sqlite3.Error as exc:
                conn.rollback()
                raise
        return result.rowcount
    except sqlite3.Error as exc:
        log.error('cache %s: failed to flush: %s', cache, str(exc))
        raise CommandExecutionError(str(exc))


def vacuum(cache, max_entries=None):
    '''
    Run a vacuum on the cache database file if the cache is not too full.
    '''
    if max_entries is None:
        max_entries = VACUUM_MAX_ENTRIES
    query = 'SELECT COUNT(*) FROM {table}'.format(table=TABLE_NAME)
    try:
        with _get_conn(cache) as conn:
            entries = conn.execute(query).fetchone()[0]
            if entries <= max_entries:
                start = time.time()
                conn.execute('VACUUM')
                _update_last_vacuum_time(conn, start)
                log.info('cache %s: vacuum finished in %d msec, database contains %d entries',
                        cache, int(1000 * (time.time() - start)), entries)
                return True
            else:
                log.info('cache %s: skipping vacuum due to database size (%d entries, limit is %d)',
                        cache, entries, max_entries)
                return False
    except sqlite3.Error as exc:
        log.error('cache %s: vacuum failed: %s', cache, str(exc))
        raise CommandExecutionError(str(exc))
