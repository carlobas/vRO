# coding: utf-8

'''
Decorators!
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
import functools
import hashlib
import json
import logging

# Import SSEAPE libs
import sseape.utils.json

log = logging.getLogger(__name__)


def _checksum_data(data):
    '''
    Generate a checksum of a data structure in a repeatable way
    '''
    hashable = json.dumps(data,
                          cls=sseape.utils.json.JSONEncoder,
                          sort_keys=True).encode('utf-8')
    return hashlib.sha256(hashable).hexdigest()


def skip_if_unchanged(*attrname_list, **decorator_kwargs):
    '''
    Skip invoking a method if a checksum of the data is unchanged since the
    previous invocation. The data must be present in an attribute on the class
    and it must be JSON serializable. If the method yields something that
    evalutes to boolean false, it is assumed to have failed and the checksum
    will not be updated.

    An optional `magic` keyword argument can be passed with the name of a
    special attribute on the class. A change in the value of this attribute
    since the last invocation causes any saved checksum values to be ignored,
    forcing the function to be invoked regardless of whether the data has
    changed.

    Usage:

        class MyClass():
            foo = 'Foo'
            bar = 'Bar'

            @skip_if_unchanged('foo', 'bar')
            def expensive_thing(self):
                if datetime.datetime.now().second % 2 == 0:
                    self.foo = 'Foo!'
    '''
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            should_invoke_func = False
            checksum_map = {}

            magic = decorator_kwargs.get('magic')
            if magic:
                prev_magic_attr = '__{0}_magic'.format(func.__name__)
                prev_magic = getattr(self, prev_magic_attr, None)
                curr_magic = getattr(self, magic, None)
                if prev_magic != curr_magic:
                    should_invoke_func = True
                    setattr(self, prev_magic_attr, curr_magic)
                    log.debug(
                        "Invocation of '%s' forced due to changed magic '%s'.",
                        func.__name__, magic
                    )

            for attrname in attrname_list:
                if not hasattr(self, attrname):
                    continue

                checksum_attr = '__{0}_checksum'.format(attrname)
                prev_checksum = getattr(self, checksum_attr, None)
                checksum = _checksum_data(getattr(self, attrname, None))

                checksum_map[checksum_attr] = checksum
                if checksum != prev_checksum:
                    should_invoke_func = True

            if should_invoke_func:
                result = func(self, *args, **kwargs)
                if result is not False:
                    for checksum_attr, checksum in checksum_map.items():
                        setattr(self, checksum_attr, checksum)
                else:
                    log.debug("'%s' returned False; discarding checksum", func.__name__)
                    for checksum_attr, checksum in checksum_map.items():
                        setattr(self, checksum_attr, None)
            else:
                log.debug("Skipping '%s'; checksum unchanged.", func.__name__)
        return wrapper
    return decorator
