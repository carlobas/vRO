# coding: utf-8
'''
JSON utils
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

# Import 3rd-party libs
import sseapiclient.serialize

# Import salt libs
try:
    from salt.utils.context import NamespacedDictWrapper
    HAS_NAMESPACED_DICT_WRAPPER = True
except ImportError:
    HAS_NAMESPACED_DICT_WRAPPER = False


class JSONEncoder(sseapiclient.serialize.JSONEncoder):
    '''
    JSON encoder to handle salt's NamespacedDictWrapper
    '''
    def default(self, obj):  # pylint: disable=method-hidden
        if HAS_NAMESPACED_DICT_WRAPPER and isinstance(obj, NamespacedDictWrapper):
            return obj._dict()  # pylint: disable=protected-access
        return super(JSONEncoder, self).default(obj)
