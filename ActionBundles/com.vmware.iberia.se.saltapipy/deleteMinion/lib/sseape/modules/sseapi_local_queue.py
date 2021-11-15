# coding: utf-8
'''
SSE local queue for json objects
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
import json
import logging
import os
import sqlite3
import time

# Import Salt libs
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

__virtualname__ = 'sseapi_local_queue'

QUEUE_TABLE = 'queue'
QUEUE_TABLE_DEF = '(id INTEGER PRIMARY KEY, timestamp REAL, data TEXT)'

META_TABLE = 'metadata'
META_TABLE_DEF = '(key TEXT PRIMARY KEY, value BLOB)'

# Maximum time (milliseconds) to spend retrying to open the database when
# SQLite reports that it is locked.
LOCK_RETRY_LIMIT = 2000

# Default maximum number of entries to allow in the database when running a
# vacuum. If the database contains more entries than this, the vacuum will be
# skipped. The default value is derived from testing with a laptop SSD (2019),
# where vacuum handles about 350MB of data per second. Assuming an average row
# size of 1000 bytes, a vacuum operation should take less than a second.
VACUUM_MAX_ENTRIES = 350000


def __virtual__():
    # Just need sqlite3, should be good to go
    return __virtualname__


class QueueConn(sqlite3.Connection):
    '''
    Connection wrapper that puts the database file in the right place and adds
    logging to some methods. Could use Connection.set_trace_callback() for
    logging but that works only in Python 3.
    '''
    def __init__(self, queue, *args, **kwargs):
        self.open = False
        self.queue = queue
        self.dbfile = os.path.join(__opts__['cachedir'], '{}.sqlite3'.format(self.queue))

        if kwargs.pop('create', True) is False:
            # If the caller does not want to create the database file, try to
            # open it, causing an exception to be raised when it does not
            with open(self.dbfile, 'r'):  # pylint: disable=resource-leakage
                pass

        log.debug('queue %s: opening database %s', self.queue, self.dbfile)
        super(QueueConn, self).__init__(self.dbfile, *args, **kwargs)
        self.open = True
        self.execute('pragma journal_mode=wal')
        self.execute('pragma synchronous=normal')

    def __del__(self):
        if self.open:
            log.debug('queue %s: closed database %s', self.queue, self.dbfile)

    def execute(self, sql, *params):
        log.debug('queue %s: sql: %s', self.queue, sql)
        return super(QueueConn, self).execute(sql, *params)

    def executemany(self, sql, *params):
        log.debug('queue %s: sql: %s', self.queue, sql)
        return super(QueueConn, self).executemany(sql, *params)


def _get_conn(queue):
    '''
    Get a connection to the queue database. If the database is locked, retry a
    few times.
    '''
    start = time.time()
    while True:
        try:
            conn = QueueConn(queue)
            for (table, table_def) in ((QUEUE_TABLE, QUEUE_TABLE_DEF),
                                       (META_TABLE, META_TABLE_DEF)):
                cmd = 'CREATE TABLE IF NOT EXISTS {table} {table_def}'.format(table=table, table_def=table_def)
                conn.execute(cmd)
            return conn
        except sqlite3.OperationalError as exc:
            if 'database is locked' in str(exc):
                remain = LOCK_RETRY_LIMIT - int(1000 * (time.time() - start))
                if remain > 0:
                    log.debug('queue %s: %s: will retry for %d more msec', queue, str(exc), remain)
                    time.sleep(0.1)
                    continue
            raise


def _get_size(conn):
    '''
    Get queue size in items using an open connection
    '''
    with conn:
        cmd = 'SELECT COUNT(*) FROM {table}'.format(table=QUEUE_TABLE)
        result = conn.execute(cmd).fetchone()
        return result[0]


def queue_exists(queue):
    '''
    Tell whether a queue exists. Useful for callers that want to use the queue
    if it exists but not create it otherwise.
    '''
    try:
        QueueConn(queue, create=False)
        return True
    except Exception:  # pylint: disable=broad-except
        return False


def get_size(queue):
    '''
    Get queue size in items
    '''
    try:
        with _get_conn(queue) as conn:
            return _get_size(conn)
    except sqlite3.Error as exc:
        log.error('queue %s: failed to get queue size', queue)
        raise CommandExecutionError(str(exc))


def purge(queue, age_limit=None, age_limit_abs=None, size_limit=None):
    '''
    Remove old items from a queue in order to enforce age and size limits.

    Pass `age_limit` to purge items with timestamps older than N seconds ago.

    Pass `age_limit_abs` to purge items with timestamps older than an absolute
    Unix timestamp value.

    Pass `size_limit` to purge the items with the oldest timestamps if
    necessary to reduce the size of the queue to the specified limit.
    '''
    try:
        del_age = del_age_abs = del_size = 0
        with _get_conn(queue) as conn:
            if age_limit is not None:
                try:
                    old = time.time() - age_limit
                    cmd = 'DELETE FROM {table} WHERE timestamp < {old}'.format(table=QUEUE_TABLE, old=old)
                    del_age = conn.execute(cmd).rowcount
                    conn.commit()
                except sqlite3.Error as exc:
                    conn.rollback()
                    raise

            if age_limit_abs is not None:
                try:
                    cmd = 'DELETE FROM {table} WHERE timestamp <= {limit}'.format(table=QUEUE_TABLE, limit=age_limit_abs)
                    del_age_abs = conn.execute(cmd).rowcount
                    conn.commit()
                except sqlite3.Error as exc:
                    conn.rollback()
                    raise

            if size_limit is not None:
                queue_size = _get_size(conn)
                if queue_size > size_limit:
                    del_count = queue_size - size_limit
                    try:
                        cmd = ('DELETE FROM {table} WHERE id IN '
                               '(SELECT id FROM {table} ORDER BY timestamp LIMIT {limit})').format(
                                       table=QUEUE_TABLE, limit=del_count)
                        del_size = conn.execute(cmd).rowcount
                        conn.commit()
                    except sqlite3.Error as exc:
                        conn.rollback()
                        raise
        del_total = del_age + del_age_abs + del_size
        if del_total:
            log.info('queue %s: purged %d items (%d due to relative age, %d due to absolute age, %d due to size limit)',
                    queue, del_total, del_age, del_size, del_age_abs)
        return del_total
    except sqlite3.Error as exc:
        log.error('queue %s: failed to purge old items: %s', queue, str(exc))
        raise CommandExecutionError(str(exc))


def push(queue, items):
    '''
    Push items onto a queue. Each item is a dict containing 'data' and an
    optional 'timestamp' (defaults to now).
    '''
    try:
        cmd = 'INSERT INTO {table} (timestamp, data) VALUES (?, ?)'.format(table=QUEUE_TABLE)
        args = [(item.get('timestamp') or time.time(), json.dumps(item['data']))
                for item in items]
        with _get_conn(queue) as conn:
            try:
                conn.executemany(cmd, args)
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                raise
        log.info('queue %s: pushed %d items', queue, len(items))
        return len(items)
    except sqlite3.Error as exc:
        log.error('queue %s: failed to push %d items: %s', queue, len(items), str(exc))
        raise CommandExecutionError(str(exc))


def pop(queue, limit=1):
    '''
    Pop items from a queue in timestamp order and return them
    '''
    try:
        items = []
        select = 'SELECT id, timestamp, data FROM {table} ORDER BY timestamp'.format(table=QUEUE_TABLE)
        with _get_conn(queue) as conn:
            queue_size = _get_size(conn)
            remain = min(queue_size, limit)
            while remain > 0:
                try:
                    # Pop items in batches to accommodate sqlite's "SQL
                    # variables" limit. Since Python doesn't expose the limit
                    # programmatically, use 999 (the default limit for sqlite
                    # <3.32) as a safe limit.
                    query_limit = min(999, remain)
                    cmd = select + ' LIMIT {limit}'.format(limit=query_limit)
                    results = conn.execute(cmd).fetchall()
                    if results:
                        items.extend([{'timestamp': item[1],
                                       'data': json.loads(item[2])}
                                      for item in results])
                        del_ids = [item[0] for item in results]
                        ids_str = ','.join(['?'] * len(del_ids))
                        del_cmd = '''DELETE FROM {table} WHERE id IN ({ids})'''.format(
                                table=QUEUE_TABLE, ids=ids_str)
                        conn.execute(del_cmd, del_ids)
                        remain -= len(results)
                    else:
                        remain = 0
                except sqlite3.Error as exc:
                    conn.rollback()
                    raise
            conn.commit()
            log.info('queue %s: popped %d items', queue, len(items))
        return items
    except sqlite3.Error as exc:
        log.error('queue %s: failed to pop items: %s', queue, str(exc))
        raise CommandExecutionError(str(exc))


def vacuum(queue, max_entries=None):
    '''
    Run a vacuum on the queue database file. If the database contains less than
    the maximum number of entries, do the vacuum and return True. Otherwise
    skip the vacuum and return False.
    '''
    if max_entries is None:
        max_entries = VACUUM_MAX_ENTRIES
    try:
        with _get_conn(queue) as conn:
            query = 'SELECT COUNT(*) FROM {table}'.format(table=QUEUE_TABLE)
            entries = conn.execute(query).fetchone()[0]
            if entries <= max_entries:
                start = time.time()
                conn.execute('VACUUM')
                log.info('queue %s: vacuum finished in %d msec, database contains %d entries',
                        queue, int(1000 * (time.time() - start)), entries)
                return True
            else:
                log.info('queue %s: skipping vacuum due to database size (%d entries, limit is %d)',
                        queue, entries, max_entries)
                return False
    except sqlite3.Error as exc:
        log.error('queue %s: vacuum failed: %s', queue, str(exc))
        raise CommandExecutionError(str(exc))


def get_metadata(queue, key):
    '''
    Get a queue metadata item.
    '''
    query = 'SELECT value FROM {table} WHERE key = {key!r}'.format(table=META_TABLE, key=key)
    try:
        with _get_conn(queue) as conn:
            result = conn.execute(query).fetchone()
            if result is None:
                log.info('queue %s: no metadata item %s', queue, key)
                return None
            else:
                value = result[0]
                log.info('queue %s: found metadata item %s=%s', queue, key, value)
                return value
    except sqlite3.Error as exc:
        log.error('queue %s: failed to get metadata item %s', queue, key)
        raise CommandExecutionError(str(exc))


def set_metadata(queue, key, value):
    '''
    Set a queue metadata item.
    '''
    if value is None:
        valstr = 'NULL'
    elif isinstance(value, (bytes, bytearray)):
        valstr = "x'{}'".format(value.hex())
    else:
        valstr = '{!r}'.format(value)

    try:
        query = 'INSERT OR REPLACE INTO {table} VALUES ({key!r}, {value})'.format(table=META_TABLE, key=key, value=valstr)
        with _get_conn(queue) as conn:
            try:
                conn.execute(query)
            except sqlite3.Error as exc:
                conn.rollback()
                raise
        log.info('queue %s: set metadata item %s=%s', queue, key, value)
    except sqlite3.Error as exc:
        log.error('queue %s: failed to set metadata item %s=%s', queue, key, value)
        raise CommandExecutionError(str(exc))


def delete_metadata(queue, key):
    '''
    Delete a queue metadata item.
    '''
    try:
        query = 'DELETE FROM {table} WHERE key = {key!r}'.format(table=META_TABLE, key=key)
        with _get_conn(queue) as conn:
            try:
                deleted = conn.execute(query).rowcount
                conn.commit()
                if deleted:
                    log.info('queue %s: deleted metadata item %s', queue, key)
                else:
                    log.info('queue %s: no metadata item %s', queue, key)
                return deleted
            except sqlite3.Error as exc:
                conn.rollback()
                raise
    except sqlite3.Error as exc:
        log.error('queue %s: failed to delete metadata item %s', queue, key)
        raise CommandExecutionError(str(exc))
