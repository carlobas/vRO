# -*- coding: utf-8 -*-
'''
Return data to a PostgreSQL server with json data stored in Pg's jsonb data type

:maintainer:    Dave Boucha <dave@saltstack.com>, Seth House <shouse@saltstack.com>, C. R. Oldham <cr@saltstack.com>
:maturity:      new
:depends:       python-psycopg2
:platform:      all

To enable this returner, the minion will need the python client for PostgreSQL
installed and the following values configured in the minion or master
config. These are the defaults:

.. code-block:: yaml

    returner.pgjsonb.host: 'salt'
    returner.pgjsonb.user: 'salt'
    returner.pgjsonb.pass: 'salt'
    returner.pgjsonb.db: 'salt'
    returner.pgjsonb.port: 5432

SSL is optional. The defaults are set to None. If you do not want to use SSL,
either exclude these options or set them to None.

.. code-block:: yaml

    returner.pgjsonb.ssl_ca: None
    returner.pgjsonb.ssl_cert: None
    returner.pgjsonb.ssl_key: None

Alternative configuration values can be used by prefacing the configuration
with `alternative.`. Any values not found in the alternative configuration will
be pulled from the default location. As stated above, SSL configuration is
optional. The following ssl options are simply for illustration purposes:

.. code-block:: yaml

    alternative.pgjsonb.host: 'salt'
    alternative.pgjsonb.user: 'salt'
    alternative.pgjsonb.pass: 'salt'
    alternative.pgjsonb.db: 'salt'
    alternative.pgjsonb.port: 5432
    alternative.pgjsonb.ssl_ca: '/etc/pki/mysql/certs/localhost.pem'
    alternative.pgjsonb.ssl_cert: '/etc/pki/mysql/certs/localhost.crt'
    alternative.pgjsonb.ssl_key: '/etc/pki/mysql/certs/localhost.key'

Use the following Pg database schema:

.. code-block:: sql

    CREATE DATABASE  salt
      WITH ENCODING 'utf-8';

    --
    -- Table structure for table `jids`
    --
    DROP TABLE IF EXISTS jids;
    CREATE TABLE jids (
       jid varchar(255) NOT NULL primary key,
       load jsonb NOT NULL
    );
    CREATE INDEX idx_jids_jsonb on jids
           USING gin (load)
           WITH (fastupdate=on);

    --
    -- Table structure for table `salt_returns`
    --

    DROP TABLE IF EXISTS salt_returns;
    CREATE TABLE salt_returns (
      fun varchar(50) NOT NULL,
      jid varchar(255) NOT NULL,n
      return jsonb NOT NULL,
      id varchar(255) NOT NULL,
      success varchar(10) NOT NULL,
      full_ret jsonb NOT NULL,
      alter_time TIMESTAMP WITH TIME ZONE DEFAULT NOW());

    CREATE INDEX idx_salt_returns_id ON salt_returns (id);
    CREATE INDEX idx_salt_returns_jid ON salt_returns (jid);
    CREATE INDEX idx_salt_returns_fun ON salt_returns (fun);
    CREATE INDEX idx_salt_returns_return ON salt_returns
        USING gin (return) with (fastupdate=on);
    CREATE INDEX idx_salt_returns_full_ret ON salt_returns
        USING gin (full_ret) with (fastupdate=on);

    --
    -- Table structure for table `salt_events`
    --

    DROP TABLE IF EXISTS salt_events;
    DROP SEQUENCE IF EXISTS seq_salt_events_id;
    CREATE SEQUENCE seq_salt_events_id;
    CREATE TABLE salt_events (
        id BIGINT NOT NULL UNIQUE DEFAULT nextval('seq_salt_events_id'),
        tag varchar(255) NOT NULL,
        data jsonb NOT NULL,
        alter_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        master_id varchar(255) NOT NULL);

    CREATE INDEX idx_salt_events_tag on
        salt_events (tag);
    CREATE INDEX idx_salt_events_data ON salt_events
        USING gin (data) with (fastupdate=on);

Required python modules: Psycopg2

To use this returner, append '--return pgjsonb' to the salt command.

.. code-block:: bash

    salt '*' test.ping --return pgjsonb

To use the alternative configuration, append '--return_config alternative' to the salt command.

.. versionadded:: 2015.5.0

.. code-block:: bash

    salt '*' test.ping --return pgjsonb --return_config alternative

To override individual configuration items, append --return_kwargs '{"key:": "value"}' to the salt command.

.. versionadded:: 2016.3.0

.. code-block:: bash

    salt '*' test.ping --return pgjsonb --return_kwargs '{"db": "another-salt"}'

'''

# Copyright (C) 2020 SaltStack, Inc.
#
# This file is licensed only for use with SaltStack's Enterprise software
# product and may not be used for any other purpose without prior written
# authorization from SaltStack, Inc.  The license terms governing your use of
# Salt Stack Enterprise also govern your use of this file. See license terms at
# https://www.saltstack.com/terms/

# Let's not allow PyLint complain about string substitution
# pylint: disable=W1321,E1321

# Import Python libs
from __future__ import absolute_import
import datetime
import json
import logging
import random
from contextlib import contextmanager

# Import Salt libs
import salt.exceptions
import salt.returners
import salt.utils.jid

try:
    import psycopg2
    import psycopg2.extras
    HAS_PG = True
except ImportError:
    HAS_PG = False

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'sse_pgjsonb'


def __virtual__():
    if not HAS_PG:
        return False, 'Pg driver not loaded (psycopg2)'
    return True


def _get_options(ret=None):
    '''
    Returns options used for the MySQL connection.
    '''
    defaults = {'host': 'localhost',
                'user': 'salt',
                'pass': 'salt',
                'db': 'salt',
                'port': 5432}

    attrs = {'host': 'host',
             'user': 'user',
             'pass': 'pass',
             'db': 'db',
             'port': 'port',
             'sslmode': 'sslmode',
             'sslcert': 'sslcert',
             'sslkey': 'sslkey',
             'sslrootcert': 'sslrootcert',
             }

    _options = salt.returners.get_returner_options('returner.{0}'.format(__virtualname__),
                                                   ret,
                                                   attrs,
                                                   __salt__=__salt__,
                                                   __opts__=__opts__,
                                                   defaults=defaults)
    # _options.update(salt.config.master_config('/etc/salt/master'))
    # Ensure port is an int
    if 'port' in _options:
        _options['port'] = int(_options['port'])
    return _options


conn = None
log_flag = True


@contextmanager
def _get_serv(ret=None, commit=False):
    '''
    Return a Pg cursor
    '''
    global conn, log_flag
    if not conn:
        _options = _get_options(ret)
        try:
            # psycopg2 defaults to SSL if available
            # sslmode = 'disable' is required to disable SSL
            ssl_options = {}
            if _options.get('sslmode'):
                ssl_options['sslmode'] = _options.get('sslmode')
            if _options.get('sslrootcert'):
                ssl_options['sslrootcert'] = _options.get('sslrootcert')
            if _options.get('sslcert'):
                ssl_options['sslcert'] = _options.get('sslcert')
            if _options.get('sslkey'):
                ssl_options['sslkey'] = _options.get('sslkey')
            conn = psycopg2.connect(host=_options.get('host'),
                                    user=_options.get('user'),
                                    password=_options.get('pass'),
                                    database=_options.get('db'),
                                    port=_options.get('port'),
                                    **ssl_options)
            conn.set_session(autocommit=True)
            # always log connection events, use "warn" because
            # it is a default setting
            log.info('pgjsonb returner successfully connected to database')
            log_flag = True

        except (psycopg2.OperationalError, psycopg2.DatabaseError) as exc:
            # reset the global connection,
            # next attempt will attempt to reconnect
            conn = None
            if log_flag:
                log.error('pgjsonb returner could not connect to database ')
                log.error(str(exc))
                # suppress subsequent duplicate errors
                log_flag = False
                raise salt.exceptions.SaltMasterError(str(exc))

    cursor = None
    try:
        cursor = conn.cursor()
        yield cursor
        # successful
        log_flag = True
    except psycopg2.DatabaseError as err:
        # connection is always closed when this exception
        # is reached so retries are futile at this point...
        # event is discarded using "lesser of evils" principle
        # reset the global connection, the next DB r/w will
        # attempt to reconnect automatically
        conn = None
        if log_flag:
            log.error('pgjsonb returner could not r/w to database: ')
            log.error(str(err))
            # suppress subsequent duplicate errors
            log_flag = False
            # raise salt.exceptions.SaltMasterError(str(err))
    finally:
        if cursor is not None:
            cursor.close()


def returner(ret):
    '''
    Return data to a Pg server
    '''
    # this function now stubbed out because this table
    # is automatically updated by a trigger in
    # the Pg Database which does the insert when
    # the corresponding salt_event is inserted.
    return

    # try:
    #     with _get_serv(ret, commit=True) as cur:
    #         sql = '''INSERT INTO salt_returns
    #                 (fun, jid, return, id, success, full_ret, alter_time)
    #                 VALUES (%s, %s, %s, %s, %s, %s, %s)'''
    #
    #         cur.execute(sql, (ret['fun'], ret['jid'],
    #                           psycopg2.extras.Json(ret['return']),
    #                           ret['id'],
    #                           ret.get('success', False),
    #                           psycopg2.extras.Json(ret),
    #                           time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime())))
    # except salt.exceptions.SaltMasterError:
    #     log.critical('Could not store return with pgjsonb returner. PostgreSQL server unavailable.')


def event_return(events):
    '''
    Return event to Pg server

    Requires that configuration be enabled via 'event_return'
    option in master config.
    '''
    with _get_serv(events, commit=True) as cur:
        sql = 'INSERT INTO salt_events (tag, data, master_id, alter_time) VALUES %s'
        values = []
        total_events = len(events)
        log.debug('About to send %s events to database', total_events)
        for event in events:
            tag = event.get('tag', '')
            data = event.get('data', '')
            vals = (tag,
                    psycopg2.extras.Json(data),
                    __opts__['id'],
                    datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
            values.append(vals)

        if values:
            log.debug('Sending %s events in batch to execute_values', total_events)
            start = datetime.datetime.now()
            psycopg2.extras.execute_values(cur, sql, values, template=None, page_size=10000)
            elapsed = datetime.datetime.now() - start
            log.info('sse_pgjsonb sent %s events in %s', total_events, elapsed)


MY_MASTER_UUID = ''


def _get_my_master_uuid():
    # request from DB and cache the uuid for this master
    global MY_MASTER_UUID
    if MY_MASTER_UUID == '':
        with _get_serv(commit=True) as cur:
            sql = "SELECT uuid FROM masters WHERE master_id = '{0}' LIMIT 1".format(__opts__['id'])
            cur.execute(sql)
            rows = cur.fetchall()
            MY_MASTER_UUID = rows[0][0]
    return MY_MASTER_UUID


def save_load(jid, load, minions=None):
    '''
    Save the load to the specified jid id
    '''
    with _get_serv(commit=True) as cur:

        sql = '''INSERT INTO jids
               (master_uuid, jid, "user", load)
                VALUES (%s, %s, %s, %s)'''

        try:
            user = load.get('user', 'root')  # default = 'root'
            cur.execute(sql, (_get_my_master_uuid(), jid, user, psycopg2.extras.Json(load)))
        except psycopg2.IntegrityError:
            # https://github.com/saltstack/salt/issues/22171
            # Without this try:except: we get tons of duplicate entry errors
            # which result in job returns not being stored properly
            pass


def save_minions(jid, minions):  # pylint: disable=unused-argument
    '''
    Included for API consistency
    '''
    pass  # pylint: disable=unnecessary-pass


def get_load(jid):
    '''
    Return the load data that marks a specified jid
    '''
    with _get_serv(ret=None, commit=True) as cur:

        sql = '''SELECT load FROM jids WHERE jid = '{0}';'''.format(jid)
        cur.execute(sql)
        data = cur.fetchone()
        if data:
            return data[0]
        return {}


def get_jid(jid):
    '''
    Return the information returned when the specified job id was executed
    '''
    with _get_serv(ret=None, commit=True) as cur:
        sql = '''SELECT minion_id, full_ret FROM salt_returns
                JOIN masters ON masters.uuid = salt_returns.master_uuid
                WHERE salt_returns.jid = '%s'
                AND (masters.master_id = %s OR masters.cluster_id = %s);'''

        cur.execute(sql, (int(jid), __opts__['id'], __opts__['id']))
        data = cur.fetchall()
        ret = {}
        if data:
            for minion, full_ret in data:
                ret[minion] = full_ret
        return ret


def get_fun(fun):
    '''
    Return a dict of the last function called for all minions
    '''
    with _get_serv(ret=None, commit=True) as cur:

        sql = '''SELECT s.minion_id, s.jid, s.full_ret
                  FROM salt_returns s
                  JOIN (SELECT max(jid) as jid
                        FROM salt_returns GROUP BY fun, minion_id) max
                  ON s.jid = max.jid
                  WHERE s.fun = \'{0}\' AND s.master_uuid =
                  (SELECT uuid FROM masters WHERE master_id = \'{1}\')'''.format(
            fun,
            __opts__['id'])

        cur.execute(sql)
        data = cur.fetchall()

        ret = {}
        if data:
            for minion, _, full_ret in data:
                ret[minion] = json.loads(str(full_ret))
        return ret


def get_jids():
    '''
    Return a list of all job ids
    '''
    with _get_serv(ret=None, commit=True) as cur:

        sql = '''SELECT jid, load
                FROM jids'''

        cur.execute(sql)
        data = cur.fetchall()
        ret = {}
        for jid, load in data:
            ret[jid] = salt.utils.jid.format_jid_instance(jid, load)
        return ret


def get_minions():
    '''
    Return a list of minions
    '''
    with _get_serv(ret=None, commit=True) as cur:
        # sql = '''SELECT DISTINCT master_uuid, minion_id
        #         FROM salt_returns'''
        sql = '''SELECT DISTINCT minion_id
                FROM salt_returns WHERE master_uuid =
                (SELECT uuid FROM masters WHERE master_id = \'{0}\')'''.format(
            __opts__['id'])

        cur.execute(sql)
        data = cur.fetchall()
        ret = []
        for minion in data:
            ret.append(minion[0])
        return ret


def prep_jid(nocache=False, passed_jid=None):  # pylint: disable=unused-argument
    '''
    Do any work necessary to prepare a JID, including sending a custom id
    '''
    return _gen_jid(passed_jid)


def close_db_connection():
    """
    needed for clean shutdown of Postgres DB
    Failure to call this function on close will cause a
    nasty pg log message.
    """
    global conn
    if conn:
        conn.close()


def _gen_jid(passed_jid):
    if passed_jid is not None:
        return passed_jid
    # Generate a JID
    try:
        jid = salt.utils.jid.gen_jid(__opts__)  # pylint: disable=too-many-function-args
    except TypeError:
        # https://github.com/saltstack/salt/commit/3c58717c5881ec4ecc50f0c699f8ddd355c35569
        jid = salt.utils.jid.gen_jid()  # pylint: disable=no-value-for-parameter
    # Return the same JID with randomized microseconds
    return '{0}{1:06d}'.format(jid[:-6], random.randint(0, 999999))


def clean_old_jobs():
    '''
    This is not implemented here in the returner, we clean out the jobs via RaaS
    '''
    pass  # pylint: disable=unnecessary-pass
