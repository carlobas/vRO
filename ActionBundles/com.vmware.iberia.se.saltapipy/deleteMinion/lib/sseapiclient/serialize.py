# -*- coding: utf-8 -*-
'''
    :codeauthor: :email:`Pedro Algarvio (pedro@algarvio.me)`
    :copyright: © 2016 by the SaltStack Team, see AUTHORS for more details.
    :license: Apache 2.0, see LICENSE for more details.


    sseapiclient.serialize
    ~~~~~~~~~~~~~~~~~~~~~~

    Serialization helpers
'''

# Import Python libs
from __future__ import absolute_import, print_function
import collections
import datetime
import json
import uuid

# pylint: disable=ungrouped-imports
try:
    from collections.abc import Iterator
except ImportError:
    # Python 2
    from collections import Iterator
# pylint: enable=ungrouped-imports


def json_dumps(obj, cls=None):
    '''
    JSON dump the provided object with our custom JSON encoder
    '''
    if cls is None:
        cls = JSONEncoder
    return json.dumps(obj, cls=cls)


class JSONEncoder(json.JSONEncoder):

    def default(self, obj):  # pylint: disable=method-hidden,arguments-differ
        if isinstance(obj, collections.Set):
            return list(obj)
        if hasattr(obj, 'union') and hasattr(obj, 'intersection'):
            # when blist is not installed, cassandra.utils.sortedset is a plain
            # class mimicking blist.sortedset
            return list(obj)
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if isinstance(obj, Iterator):
            # This will catch generator types under Python and Cython
            return list(obj)
        return super(JSONEncoder, self).default(obj)
