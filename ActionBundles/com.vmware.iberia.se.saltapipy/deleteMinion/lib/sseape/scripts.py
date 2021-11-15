# -*- coding: utf-8 -*-
'''
    sseape.scripts
    ~~~~~~~~~~~~~~

    This will print out example configuration
'''

# Copyright (C) 2020 SaltStack, Inc.
#
# This file is licensed only for use with SaltStack's Enterprise software
# product and may not be used for any other purpose without prior written
# authorization from SaltStack, Inc.  The license terms governing your use of
# Salt Stack Enterprise also govern your use of this file. See license terms at
# https://www.saltstack.com/terms/

# Import Python libs
from __future__ import absolute_import, print_function
from optparse import OptionParser  # pylint: disable=deprecated-module

# Import SSEAPE libs
import sseape.utils.config as sseape_config


def main():
    parser = OptionParser()
    parser.add_option(
        '--ext-modules',
        action='store_true',
        default=False,
        help='Print out the external extension modules directories settings')
    parser.add_option(
        '--default-config',
        action='store_true',
        default=False,
        help='Print out the default configuration settings')
    parser.add_option(
        '--all',
        action='store_true',
        default=False,
        help='This is the same as passing --ext-modules and --default-config')
    parser.add_option(
        '--returner',
        default='sseapi')
    parser.add_option(
        '--fileserver-update-interval',
        action='store',
        type='int',
        dest='fileserver_update_interval',
        default=60)
    parser.add_option(
        '--timeout',
        action='store',
        type='int',
        dest='timeout',
        default=15)
    options, args = parser.parse_args()
    kwargs = {
        'ext_modules': options.ext_modules or options.all,
        'default_config': options.default_config or options.all,
        'returner': options.returner,
        'fs_update_interval': options.fileserver_update_interval
    }
    print(sseape_config.generate(**kwargs))
    parser.exit(0)
