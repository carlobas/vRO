# -*- coding: utf-8 -*-
'''
    sseape.loader
    ~~~~~~~~~~~~~

    SSEAPE Loader
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
import os

PKG_DIR = os.path.abspath(os.path.dirname(__file__))


def beacons_dirs():
    yield os.path.join(PKG_DIR, 'beacons')


def engines_dirs():
    yield os.path.join(PKG_DIR, 'engines')


def fileserver_dirs():
    yield os.path.join(PKG_DIR, 'fileserver')


def pillar_dirs():
    yield os.path.join(PKG_DIR, 'pillar')


def returner_dirs():
    yield os.path.join(PKG_DIR, 'returners')


def roster_dirs():
    yield os.path.join(PKG_DIR, 'roster')


def runner_dirs():
    yield os.path.join(PKG_DIR, 'runners')


def module_dirs():
    yield os.path.join(PKG_DIR, 'modules')


def proxy_dirs():
    yield os.path.join(PKG_DIR, 'proxy')


def metaproxy_dirs():
    yield os.path.join(PKG_DIR, 'metaproxy')


def states_dirs():
    yield os.path.join(PKG_DIR, 'states')
