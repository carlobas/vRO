# -*- coding: utf-8 -*-

# Copyright (C) 2020 SaltStack, Inc.
#
# This file is licensed only for use with SaltStack's Enterprise software
# product and may not be used for any other purpose without prior written
# authorization from SaltStack, Inc.  The license terms governing your use of
# Salt Stack Enterprise also govern your use of this file. See license terms at
# https://www.saltstack.com/terms/


# Import python libs
from __future__ import absolute_import

# Import SSEAPE libs
from sseape._version import get_versions
__version__ = get_versions()['version']
del get_versions
