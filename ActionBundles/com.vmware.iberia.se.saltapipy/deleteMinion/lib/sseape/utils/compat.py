# -*- coding: utf-8 -*-
'''
    sseape.utils.compat
    ~~~~~~~~~~~~~~~~~~~

    Salt imports compatability layer
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

try:
    import salt.utils.files
    fopen = salt.utils.files.fopen
except AttributeError:
    import salt.utils
    fopen = salt.utils.fopen

try:
    import salt.utils.files
    flopen = salt.utils.files.flopen
except AttributeError:
    import salt.utils
    flopen = salt.utils.flopen

try:
    import salt.utils.files
    is_fcntl_available = salt.utils.files.is_fcntl_available
except AttributeError:
    import salt.utils
    is_fcntl_available = salt.utils.is_fcntl_available

try:
    import salt.utils.files
    rm_rf = salt.utils.files.rm_rf
except AttributeError:
    import salt.utils
    rm_rf = salt.utils.rm_rf

try:
    import salt.utils.args
    format_call = salt.utils.args.format_call
except (ImportError, AttributeError):
    import salt.utils
    format_call = salt.utils.format_call

try:
    import salt.utils.hashutils
    get_hash = salt.utils.hashutils.get_hash
except (ImportError, AttributeError):
    import salt.utils
    get_hash = salt.utils.get_hash

try:
    import salt.utils.stringutils
    to_bytes = salt.utils.stringutils.to_bytes
except ImportError:
    import salt.utils
    to_bytes = salt.utils.to_bytes

try:
    import salt.utils.versions
    warn_until = salt.utils.versions.warn_until
except (ImportError, AttributeError):
    import salt.utils
    warn_until = salt.utils.warn_until
