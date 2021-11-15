# -*- coding: utf-8 -*-
'''
Execution modules for working with with HPE OneView.

These functions implement a decorator function that makes them easier to use
with either a proxy minion, or calling them directly.  The decorator
function retrieves the OneView connection object from the proxy if
this module is running on a proxy minion.  If it is not, then
each of the wrapped functions below expect at least a host,
username, and password argument.

Portions copied and adapted from example scripts at
https://github.com/HewlettPackard/python-hpOneView

Code taken from the above is
(C) Copyright (2012-2017) Hewlett Packard Enterprise Development LP

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

'''

# Copyright (C) 2020 SaltStack, Inc.
#
# This file is licensed only for use with SaltStack's Enterprise software
# product and may not be used for any other purpose without prior written
# authorization from SaltStack, Inc.  The license terms governing your use of
# Salt Stack Enterprise also govern your use of this file. See license terms at
# https://www.saltstack.com/terms/

# pylint: skip-file

# Import Python libs
from __future__ import absolute_import
import json
import logging
import re
import urllib
from functools import wraps

# Import Salt libs
import salt.utils

log = logging.getLogger(__file__)

__virtualname__ = 'hpeov'

HAS_PYTHON_ONEVIEW = False
try:
    import hpOneView as hpov
    from hpOneView.exceptions import HPOneViewException, HPOneViewTaskError
    import hpOneView.resources
    import hpOneView.resources.servers
    import hpOneView.resources.servers.server_profiles
    import hpOneView.resources.servers.server_profile_templates
    import hpOneView.resources.servers.enclosures
    from hpOneView.oneview_client import OneViewClient

    HAS_PYTHON_ONEVIEW = True
except ImportError:
    if not HAS_PYTHON_ONEVIEW:
        log.debug('Cannot load the Python library for HPE OneView')


def __virtual__():
    '''
    Only return if HPE OneView modules are available
    '''
    if HAS_PYTHON_ONEVIEW:
        return __virtualname__
    return (False, 'HPE OneView (hpeov) execution module not loaded: '
            'Cannot import hpOneView')


def format_hpov_exception(e):
    '''
    Re-formats an HPOneViewException object for returning from a failed
    Salt execution module run.
    :param e: HPOneViewException Object
    :return: Dictionary with exception details
    '''
    if hasattr(e, 'msg'):
        if '\n' not in e.msg:
            return e.msg
        else:
            (message, text_dictionary) = e.msg.split('\n')
            return eval(text_dictionary)
    else:
        return e.message


def proxy_oneview_wrap(func):
    '''
    Decorator that wraps calls to hpov functions in such a way that they
    can be called outside a proxy minion, or when running inside a proxy
    minion.  If we are running in a proxy, retrieve the connection details
    from the __proxy__ injected variable.  If we are not, then
    use the connection information passed directly with the function.
    :param func:
    :return:
    '''
    @wraps(func)
    def func_wrapper(*args, **kwargs):
        wrapped_global_namespace = func.func_globals
        kwarg_keys = kwargs.keys()
        if not (kwargs.get('host', None) and kwargs.get('username', None) and
                kwargs.get('password', None)):
            if not salt.utils.is_proxy():
                log.error('Call to hpeov module outside a proxy-minion and without credentials')
            wrapped_global_namespace['hpeov_con'] = __proxy__['hpeov.connection']()
            wrapped_global_namespace['oneview_client'] = __proxy__['hpeov.oneview_client']()
            return func(*args, **kwargs)
        else:
            credential = {'username': kwargs['username'], 'password': kwargs['password']}
            if 'domain' in kwargs:
                credential['domain'] = kwargs['domain']
            try:
                wrapped_global_namespace['hpeov_con'] = hpov.connection(kwargs['host'])
                wrapped_global_namespace['hpeov_con'].login(credential)
                wrapped_global_namespace['oneview_client'] = OneViewClient({'ip': kwargs['host'], 'credentials': DETAILS['credential']})
            except HPOneViewException as e:
                log.error('Failed to connect and login to OneView.')
                log.error('Message: {0}'.format(e.msg))
                return 'Failed to login to OneView. See log for details.'

        return func(*args, **kwargs)
    return func_wrapper


@proxy_oneview_wrap
def get_servers(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return the set of servers that OneView knows about.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of dictionaries with server details
    '''
    result = {'success': False}
    try:
        servers = oneview_client.server_hardware.get_all()
        result['success'] = True
        result['return'] = servers
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_enclosures(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return details of the enclosures OneView knows about
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of dictionaries with server details
    '''
    result = {'success': False}
    try:
        enclosures = oneview_client.enclosures.get_all()
        result['success'] = True
        result['return'] = enclosures
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_enclosure_names(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return the names of all enclosures OneView knows about
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of enclosure names
    '''
    result = {'success': False}
    try:
        enclosures = oneview_client.enclosures.get_all()
        names = []
        for encl in enclosures:
            names.append(encl['name'])
        result['success'] = True
        result['return'] = names
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_enclosure_by_name(name, host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return a single enclosure details dictionary.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: Enclosure details dictionary.
    '''
    result = {'success': False}

    try:
        enclosure = oneview_client.enclosures.get_by('name', name)
        if not enclosure:
            result['message'] = 'Not found'
            return result
        result['success'] = True
        result['return'] = enclosure
        return result
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result


@proxy_oneview_wrap
def get_server_profile_names(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return all OneView Server Profiles.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of OneView Server Profile details dictionaries
    '''
    result = {'success': False}
    names = []
    try:
        profiles =  oneview_client.server_profiles.get_all()
        for profile in profiles:
            names.append(profile['name'])
        result['success'] = True
        result['return'] = names
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_server_profiles(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return all OneView Server Profiles.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of OneView Server Profile details dictionaries
    '''
    result = {'success': False}
    try:
        profiles =  oneview_client.server_profiles.get_all()
        result['success'] = True
        result['return'] = profiles
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_server_profile_templates(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return all OneView Server Profile Templates.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of OneView Server Profile Template details dictionaries
    '''
    result = {'success': False}
    try:
        templates =  oneview_client.server_profile_templates.get_all()
        result['success'] = True
        result['return'] = templates
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_server_profile_template_names(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return list of all OneView Server Profile Template names.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of OneView Server Profile Template names.
    '''
    result = {'success': False}
    names = []
    try:
        templates =  oneview_client.server_profile_templates.get_all()
        for template in templates:
            names.append(template['name'])
        result['success'] = True
        result['return'] = names
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_server_profile_template_by_name(name, host=None, username=None,
                                        password=None, domain=None, **kwargs):
    '''
    Return a single server profile template looked up by name.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param name: Server profile template name
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of OneView Server Profile Template names.
    '''
    result = {'success': False}
    try:
        spt = oneview_client.server_profile_templates.get_by_name(name)
        if spt:
            result['success'] = True
            result['return'] = spt
        else:
            result['message'] = 'No profile by this name'
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_enclosure_groups(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return all enclosure groups that OneView knows about.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List OneView Enclosure Group Dictionaries.
    '''
    result = {'success': False}
    srv = hpov.servers(hpeov_con)
    try:
        encl_groups = srv.get_enclosure_groups()
        result['success'] = True
        result['return'] = encl_groups
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_enclosure_group_names(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return list of enclosure group names.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of OneView Enclosure Group names.
    '''
    result = {'success': False}
    srv = hpov.servers(hpeov_con)
    try:
        encl_groups = get_enclosure_groups(host=host, username=username, password=password, domain=domain)
        names = []
        for encl_group in encl_groups['return']:
            names.append(encl_group['name'])
        result['success'] = True
        result['return'] = names
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result


@proxy_oneview_wrap
def get_enclosure_group_by_name(encl_group_name, host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return a single OneView Enclosure Group details dictionary.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param encl_group_name: Name of the enclosure group to search for.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: Enclosure group details dictionary corresponding to 'encl_group_name'
    '''
    result = {'success': False}
    try:
        encl_groups = get_enclosure_groups(host=host, username=username, password=password, domain=domain)
        for encl_group in encl_groups['return']:
            if encl_group['name'] == encl_group_name:
                result['success'] = True
                result['return'] = encl_group
                return result
        result['message'] = 'Enclosure group "{0}" not found.'.format(encl_group_name)
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result


@proxy_oneview_wrap
def get_server_hardware_types(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return a list of detail dictionaries corresponding to all hardware types
    that OneView is aware of.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of dictionaries of hardware types.
    '''
    result = {'success': False}
    srv = hpov.servers(hpeov_con)
    try:
        hwt = srv.get_server_hardware_types()
        result['success'] = True
        result['return'] = hwt
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)
    return result


@proxy_oneview_wrap
def get_server_hardware_type_names(host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return a list names of hardware types that OneView is aware of.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: List of hardware type names
    '''
    result = {'success': False}
    srv = hpov.servers(hpeov_con)
    try:
        hwts = get_server_hardware_types(host=host, username=username, password=password, domain=domain)
        names = []
        for hardware_type in hwts['return']:
           names.append(hardware_type['name'])
        result['success'] = True
        result['return'] = names
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result


@proxy_oneview_wrap
def get_server_hardware_type_by_name(hwt_name, host=None, username=None, password=None, domain=None, **kwargs):
    '''
    Return a single details dictionary for the requested hardware type.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param hwt_name: Name of the type of hardware.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: Dictionary of hardware type details.
    '''
    result = {'success': False}
    try:
        hwts = get_server_hardware_types(host=host, username=username, password=password, domain=domain)
        for hardware_type in hwts['return']:
            if hardware_type['name'] == hwt_name:
                result['success'] = True
                result['return'] = hardware_type
                return result
        result['message'] = 'Hardware type "{0}" not found.'.format(hwt_name)
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result


@proxy_oneview_wrap
def create_server_profile_template(name=None,
                                   description=None,
                                   sp_description=None,
                                   hardware_type_name=None,
                                   enclosure_group=None,
                                   affinity=None,
                                   hide_flexnics=True,
                                   connection_list=None,
                                   blocking=True,
                                   host=None, username=None, password=None,
                                   domain=None, **kwargs):
    '''
    Create a OneView Server Profile Template.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param name: Name to assign to the template
    :param description: Short description for the template
    :param hardware_type_name: Name of the type of hardware for this template
    (see get_hardware_types and get_hardware_type_names)
    :param enclosure_group: Name of the enclosure group where this type of
    hardware resides
    :param affinity: 'Bay' if this template should be attached to a particular
    enclosure bay, or 'BayAndServer' if the template should be attached to
    a Bay AND a specific server.
    :param hide_flexnics: This setting controls the enumeration of physical functions that do not
    correspond to connections in a profile. Using this flag will SHOW unused
    FlexNICs to the Operating System. Changing this setting may alter the order
    of network interfaces in the Operating System. This option sets the 'Hide
    Unused FlexNICs' to disabled, eight FlexNICs will be enumerated in the
    Operating System as network interfaces for each Flex-10 or FlexFabric
    adapter.  Configuring Fibre Channel connections on a FlexFabric adapter may
    enumerate two storage interfaces, reducing the number of network interfaces
    to six. The default (this option is not selected) enables 'Hide Unused
    FlexNICs' and may suppress enumeration of FlexNICs that do not correspond
    to profile connections. FlexNICs are hidden in pairs, starting with the 4th
    pair. For instance, if the 4th FlexNIC on either physical port corresponds
    to a profile connection, all eight physical functions are enumerated. If a
    profile connection corresponds to the 2nd FlexNIC on either physical port,
    but no connection corresponds to the 3rd or 4th FlexNIC on either physical
    port, only the 1st and 2nd physical functions are enumerated in the
    Operating System.
    :param connection_list: Not implemented
    :param blocking: True to wait for the completion of the template creation,
    False to return immediately and perform creation asynchronously.
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: Dictionary with 'success' key set to True, or 'success' key
    set to False and a 'message' key with a failure indication.
    '''
    if not connection_list:
        connection_list = []
    result = {'success': False}
    srv = hpov.servers(hpeov_con)
    hwt = get_server_hardware_type_by_name(hardware_type_name, host=host,
                                           username=username, password=password,
                                           domain=domain)
    if hwt['success']:
        hwt_uri = hwt['return']['uri']
    else:
        result['message'] = hwt['message']
        return result

    encl_group = get_enclosure_group_by_name(enclosure_group)
    if encl_group['success']:
        encl_group_uri = encl_group['return']['uri']
    else:
        result['message'] = enclosure['message']
        return result

    try:
        profile_template = srv.create_server_profile_template(
            name=name, description=description, serverProfileDescription=sp_description,
            serverHardwareTypeUri=hwt_uri, affinity=affinity,
            enclosureGroupUri=encl_group_uri,
            hideUnusedFlexNics=hide_flexnics,
            profileConnectionV4=connection_list,
            blocking=blocking)
        result['success'] = True
        result['return'] = profile_template
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result


@proxy_oneview_wrap
def get_server_power_status(host=None, username=None, password=None,
                            domain=None, **kwargs):
    ret = {}
    servers = oneview_client.server_hardware.get_all()
    for s in servers:
        ret[s['name']] = s['powerState']
    return ret  

    
@proxy_oneview_wrap
def get_server_power_status_by_name(name, host=None, username=None, password=None,
                            domain=None, **kwargs):
    server = oneview_client.server_hardware.get_by('name', name)
    return server[0]['powerState']


@proxy_oneview_wrap
def set_server_power_status(name=None, power_state=None, button_press=None, host=None, username=None, password=None,
		domain=None, **kwargs):
    '''
    Valid powerControl options:
    MomentaryPress
    PressAndHold
    '''

    if type(power_state) == type(True):
      if power_state:
        power_state = "On" 
      else:
        power_state = "Off"
    config = { 'powerState': power_state, 'powerControl': button_press }

    server = oneview_client.server_hardware.get_by('name', name)
    log.debug('-------------------------')
    log.debug(server[0])
    ret = oneview_client.server_hardware.update_power_state(config, server[0]['uri'])
    log.debug(ret)
    return ret

@proxy_oneview_wrap
def delete_server_profile(name, blocking=True, force=False,
                          host=None, username=None,
                          password=None, domain=None, **kwargs):
    '''
    Delete a OneView Server Profile.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param name: Name of profile to delete
    :param blocking: Wait for task to complete
    :param force: Force profile removal
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: Dictionary with 'success' key set to True, or 'success' key
    set to False and a 'message' key with a failure indication.
    '''
    result = {'success': False}
    try:
        ret = oneview_client.server_profiles.delete_all(filter="name={0}".format(name))
        result['success'] = True
        result['profile'] = ret
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result

@proxy_oneview_wrap
def delete_server_profile_template(name, host=None, username=None,
                                   password=None, domain=None, **kwargs):
    '''
    Delete a OneView Server Profile Template.
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param name: Name of template to delete
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: Dictionary with 'success' key set to True, or 'success' key
    set to False and a 'message' key with a failure indication.
    '''
    srv = hpov.servers(hpeov_con)
    result = {'success': False}
    try:
        templates = srv.get_server_profile_templates()

        for template in templates:
            if template['name'] == name:
                ret = srv.remove_server_profile_template(template)
                result['success'] = True
                return result

        result['message'] = 'No profile template named \'{0}\''.format(name)

    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result


def _get_server(hpeov_con, srv, server_id, server_hwt, force_power_off):
    '''
    Helper function to retrieve a server for profile creation.
    :param hpeov_con: OneView connection object
    :param srv: List of server description dictionaries
    :param server_id: IP address of iLO for the server that is being targeted,
    or 'UNASSIGNED' to retrieve any server matching the hardware type that
    has no profile currently attached.
    :param server_hwt: Name of hardware type (see get_server_hardware_types)
    :param force_power_off: True to forcibly power off the targeted server if
    the unit is currently on
    :return: Return dictionary with a True/False 'success' key, and a 'message'
     key with a failure indication.
    '''

    hardware_type = None

    if server_id.upper() == 'UNASSIGNED':
        server_hw_types = srv.get_server_hardware_types()
        for ht in server_hw_types:
            if ht['name'] == server_hwt:
                hardware_type = hpeov_con.get(ht['uri'])
        if not hardware_type:
            raise HPOneViewException('Cannot find server hardware type')
        return None, hardware_type

    # Get handle for named server and power off in necessary
    servers = srv.get_servers()
    located_server = None
    for server in servers:
        ips = server['mpHostInfo']['mpIpAddresses']
        for ip in ips:
            if server_id == server['name'] or server_id == ip['address']:
                located_server = server
                if server['state'] != 'NoProfileApplied':
                    raise HPOneViewException('Server {0} already has a '
                                             'profile defined or is being '
                                             'monitored'.format(server_id))
                if server['powerState'] == 'On':
                    if force_power_off:
                        srv.set_server_powerstate(server, 'Off', force=True)
                    else:
                        raise HPOneViewException('Server {0} needs to be '
                                                 'powered off'.format(server_id))
                break
    if not located_server:
        raise HPOneViewException('Cannot find server {0}'.format(server_id))

    hardware_type = hpeov_con.get(located_server['serverHardwareTypeUri'])
    if not hardware_type:
        raise HPOneViewException('Cannot find server hardware type')

    return located_server, hardware_type


def _local_storage_settings(hardware_type, raid_level, logical_drive_noboot,
                           init_storage_controller, num_devices):
    '''
    Helper function to retrieve information about local storage settings
     for applying to a server profile.
    :param hardware_type:
    :param raid_level:
    :param logical_drive_noboot:
    :param init_storage_controller:
    :param num_devices:
    :return:
    '''
    if 'model' in hardware_type:
        model = hardware_type['model']
    else:
        raise HPOneViewException('Cannot retrieve server model')

    if raid_level or init_storage_controller:
        p = re.compile('.*DL\d.*', re.IGNORECASE)
        match = p.match(model)
        if match:
            raise HPOneViewException('Local storage management is not '
                                     'supported on DL servers')

        # FIXME -- Add a test to verify that the number of physical drives
        # is consistent with the RAID level and the number of drives in the
        # server hardware type
        # (Note taken from https://github.com/HewlettPackard/python-hpOneView/blob/master/examples/scripts/define-profile.py#L143)

        drives = []
        drives.append(hpov.common.make_LogicalDriveV3(bootable=logical_drive_noboot,
                                                      driveName=None,
                                                      driveTechnology=None,
                                                      numPhysicalDrives=num_devices,
                                                      raidLevel=raid_level))

        controller = hpov.common.make_LocalStorageEmbeddedController(
            importConfiguration=True,
            initialize=init_storage_controller,
            LogicalDrives=drives,
            managed=True,
            mode='RAID')
        local_storage = hpov.common.make_LocalStorageSettingsV3(controller)

        return local_storage

    return None


def _get_fw_settings(sts, baseline):
    '''
    Helper function to retrieve firmware baseline information.
    :param sts:
    :param baseline:
    :return:
    '''
    # Find the first Firmware Baseline
    uri = ''

    if baseline:
        # The OneView appliance converts '.' in the filename to '_', except for
        # the final one
        baseline = baseline.replace('.', '_')
        baseline = baseline.replace('_iso', '.iso')

        spps = sts.get_spps()
        for spp in spps:
            if spp['isoFileName'] == baseline:
                uri = spp['uri']
        if not uri:
            raise HPOneViewException('Firmware baseline {0} '
                                     'cannot be located'.format(baseline))

    if uri:
        fw_settings = hpov.common.make_FirmwareSettingsV3(uri, 'FirmwareOnly',
                                                          False, True)
    else:
        fw_settings = None

    return fw_settings


def _boot_settings(srv, hardware_type, disable_manage_boot, boot_order,
                   boot_mode, pxe):
    '''
    Helper function to determine managed boot order settings
    :param srv:
    :param hardware_type:
    :param disable_manage_boot:
    :param boot_order:
    :param boot_mode:
    :param pxe:
    :return:
    '''

    gen9 = False
    # Get the bootCapabilities from the Server Hardware Type
    if 'capabilities' in hardware_type and\
            'bootCapabilities' in hardware_type:
        if 'ManageBootOrder' not in hardware_type['capabilities']:
            raise HPOneViewException('Server does not support managed boot order')
        allowed_boot = hardware_type['bootCapabilities']
    else:
        raise HPOneViewException('Cannot retrieve server boot capabilities')

    if 'model' in hardware_type:
        model = hardware_type['model']
    else:
        raise HPOneViewException('Cannot identify server hardware type')

    regx = re.compile('.*Gen9.*', re.IGNORECASE)
    gen_match = regx.match(model)

    if gen_match:
        gen9 = True

    # Managed Boot Enable with Boot Options specified
    if boot_order:
        # The FibreChannelHba boot option is not exposed to the user
        if 'FibreChannelHba' in allowed_boot:
            allowed_boot.remove('FibreChannelHba')

        if len(boot_order) != len(allowed_boot):
            abo = ' '.join(allowed_boot)

            raise HPOneViewException('All supported boot options are required, '
                                     'options are {0}'.format(abo))

        # Error if the users submitted and boot option that is
        # not supported by the server hardware type
        diff = set(boot_order).difference(set(allowed_boot))
        if diff:
            raise HPOneViewException('{0} are not supported boot options for '
                                     'this server hardware type'.format(diff))

        if gen9:
            if boot_mode == 'BIOS':
                bootmode = hpov.common.make_BootModeSetting(True, boot_mode,
                                                            None)
            else:
                bootmode = hpov.common.make_BootModeSetting(True, boot_mode,
                                                            pxe)
        else:  # bootmode can not be set for Gen 7 & 8
            bootmode = None

        boot = hpov.common.make_BootSettings(boot_order, manageBoot=True)

    # Managed Boot Default value WITHOUT Boot Options specified
    # Setting boot to None uses the default from the appliance which is
    # boot.manageBoot = True.
    elif not disable_manage_boot:
        if gen9:
            if boot_mode == 'BIOS':
                bootmode = hpov.common.make_BootModeSetting(True, boot_mode,
                                                            None)
            else:
                bootmode = hpov.common.make_BootModeSetting(True, boot_mode,
                                                            pxe)

        else:  # bootmode can not be set for Gen 7 & 8
            bootmode = None

        boot = None

    # Managed Boot explicitly disabled
    elif disable_manage_boot:
        # For a Gen 9 BL server hardware "boot.manageBoot" cannot be set to
        # true unless "bootMode" is specified and "bootMode.manageMode" is set
        # to 'true'.
        p = re.compile('.*BL\d.*', re.IGNORECASE)
        match = p.match(model)
        if match:
            raise HPOneViewException('Boot mode cannot be disabled on BL servers')
        else:  # bootmode can not be set for Gen 7 & 8
            bootmode = None

        boot = hpov.common.make_BootSettings([], manageBoot=False)

    else:
        raise HPOneViewException('Unknown boot mode case')

    return boot, bootmode


def _bios_settings(bios_list):
    '''
    Helper function to load bios settings from a JSON file.
    This is not really implemented for Salt.  As it stands
    this function would need to have the JSON file locally on the
    machine running the salt-proxy.  Future versions of this execution
    module will allow this file to be created on the fly or stored
    in the salt-master's file_roots so a user could refer to it with
    the standard `salt://some_file` syntax.
    :param bios_list:
    :return:
    '''
    if bios_list:
        try:
            bios = json.loads(open(bios_list).read())

            overriddenSettings = []
            overriddenBios = {}
            for b in bios:
                overriddenSetting = {}
                overriddenSetting['id'] = b['id']
                if b['options'] and len(b['options']) > 0:
                    overriddenSetting['value'] = b['options'][0]['id']
                overriddenSettings.append(overriddenSetting)

            overriddenBios['manageBios'] = True
            overriddenBios['overriddenSettings'] = overriddenSettings
            return overriddenBios
        except ValueError:
            raise HPOneViewException('Cannot parse BIOS JSON file')


def _define_profile_v3(client, name, template_name, hw_uri, hwt_uri, osdep_uri):

# ret = _define_profile_v3(oneview_client, name, profile_template_name, server['uri'], hwt['uri'], osdep_uri)
    template = get_server_profile_template_by_name(template_name)['return']
    template.pop('uri')
    template.pop('category')
    prof = {
        "type": "ServerProfileV6",
        "serverHardwareUri": hw_uri,
        "serverHardwareTypeUri": hwt_uri,
        "name": name,
        "connections": [
            {
                "id": 1,
                "name": "Deployment Network A",
                "functionType": "Ethernet",
                "portId": "Mezz 3:1-a",
                "requestedMbps": "2500",
                "networkUri": '/rest/ethernet-networks/69d37c22-9e30-4dad-8fb8-4d62a5b1be1b',
                "boot": {
                    "priority": "Primary",
                    "initiatorNameSource": "ProfileInitiatorName",
                    "firstBootTargetIp": None,
                    "secondBootTargetIp": "",
                    "secondBootTargetPort": "",
                    "initiatorName": None,
                    "initiatorIp": None,
                    "bootTargetName": None,
                    "bootTargetLun": None
                },
                "mac": None,
                "wwpn": "",
                "wwnn": "",
                "requestedVFs": "Auto"
            },
            {
                "id": 2,
                "name": "Deployment Network B",
                "functionType": "Ethernet",
                "portId": "Mezz 3:2-a",
                "requestedMbps": "2500",
                "networkUri": '/rest/ethernet-networks/69d37c22-9e30-4dad-8fb8-4d62a5b1be1b',
                "boot": {
                    "priority": "Secondary",
                    "initiatorNameSource": "ProfileInitiatorName",
                    "firstBootTargetIp": None,
                    "secondBootTargetIp": "",
                    "secondBootTargetPort": "",
                    "initiatorName": None,
                    "initiatorIp": None,
                    "bootTargetName": None,
                    "bootTargetLun": None
                },
                "mac": None,
                "wwpn": "",
                "wwnn": "",
                "requestedVFs": "Auto"
            }
        ],
        "boot": {
            "manageBoot": True,
            "order": [
                "HardDisk"
            ]
        },
        "bootMode": {
            "manageMode": True,
            "mode": "UEFIOptimized",
            "pxeBootPolicy": "Auto"
        },
        "firmware": {
            "manageFirmware": False,
            "firmwareBaselineUri": "",
            "forceInstallFirmware": False,
            "firmwareInstallType": None
        },
        "bios": {
            "manageBios": False,
            "overriddenSettings": []
        },
        "hideUnusedFlexNics": True,
        "iscsiInitiatorName": "",
        "osDeploymentSettings": {
            "osDeploymentPlanUri": osdep_uri,
            "osVolumeUri": None
        },
        "localStorage": {
            "sasLogicalJBODs": [],
            "controllers": []
        },
        "sanStorage": None
    }
    profile = client.server_profiles.create(prof)
    return profile


def _define_profile(hpeov_con, srv, affinity, name, description, server,
                    hardware_type, boot, bootmode, fw, hide_flexnics,
                    local_storage, conn_list, san_list, bios_list,
                    profile_template_uri):
    '''
    Helper function to call out to the OneView python library to
    define a profile object.
    :param hpeov_con:
    :param srv:
    :param affinity:
    :param name:
    :param description:
    :param server:
    :param hardware_type:
    :param boot:
    :param bootmode:
    :param fw:
    :param hide_flexnics:
    :param local_storage:
    :param conn_list:
    :param san_list:
    :param bios_list:
    :return:
    '''

    if conn_list:
        # read connection list from file
        conn = json.loads(open(conn_list).read())
    else:
        conn = []

    if san_list:
        # read connection list from file
        san = json.loads(open(san_list).read())
    else:
        san = None

    # Affinity is only supported on Blade Servers so set it to None if the
    # server hardware type model does not match BL
    # p = re.compile('.*BL\d.*', re.IGNORECASE)
    # match = p.match(hardware_type['model'])
    # if not match:
    #     affinity = None

    if server:
        serverHardwareUri = server['uri']
    else:
        serverHardwareUri = None

    if conn:
        macType = 'Virtual'
        wwnType = 'Virtual'
    else:
        macType = 'Physical'
        wwnType = 'Physical'

    profile = srv.create_server_profile(affinity=affinity,
                                        biosSettings=bios_list,
                                        bootSettings=boot,
                                        bootModeSetting=bootmode,
                                        profileConnectionV4=conn,
                                        description=description,
                                        firmwareSettingsV3=fw,
                                        hideUnusedFlexNics=hide_flexnics,
                                        localStorageSettingsV3=local_storage,
                                        macType=macType,
                                        name=name,
                                        sanStorageV3=san,
                                        serverHardwareUri=serverHardwareUri,
                                        serverHardwareTypeUri=hardware_type['uri'],
                                        wwnType=wwnType,
                                        serverProfileTemplateUri=profile_template_uri)
    return profile


@proxy_oneview_wrap
def get_server_profile_by_name(name, host=None, username=None,
                               password=None, domain=None, **kwargs):
    '''
    Return a single details dictionary for the requested server profile
    Note host, username, password, and domain are not needed when this function
    is called via salt-proxy.  That information will be provided by the decorator
    in tandem with the __proxy__ injected variable.
    :param name: Name of the type of profile
    :param host: OneView hostname or IP
    :param username: OneView username
    :param password: OneView password
    :param domain: For AD installs, authentication domain
    :param kwargs: Needed because some Salt-housekeeping kwargs are passed in.
    These are generally ignored
    :return: Dictionary of hardware type details.
    '''
    result = {'success': False}
    srvprof = hpov.resources.servers.server_profiles.ServerProfiles(hpeov_con)

    try:
        profile = srvprof.get_by_name(name)
        if not profile:
            raise HPOneViewException('No profile by this name')
        result['return'] = profile
        result['success'] = True
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result


@proxy_oneview_wrap
def create_server_profile(name=None, description=None, affinity='Bay',
                          force_power_off=True, fw_baseline=None,
                          disable_manage_boot=False, boot_order=None,
                          conn_list=None, san_list=None,
                          boot_mode='BIOS', pxe='Auto', raid_level='NONE',
                          raid_phys_drives=0, logical_drive_noboot=True,
                          init_storage_controller=False, hide_flexnics=True,
                          server_id=None, hardware_type_name=None, bios_list=None,
                          profile_template_name=None, deployment_plan=None,
                          host=None, username=None, password=None,
                          domain=None, **kwargs):
    '''
    Create a OneView Server Profile
    :param name:
    :param description:
    :param affinity: This identifies the behavior of the server profile when
    the server hardware is removed or replaced. This can be set to 'Bay' or
    'BayAndServer'.
    :param force_power_off:
    :param fw_baseline:
    :param disable_manage_boot:
    :param boot_order:
    :param conn_list:
    :param san_list:
    :param boot_mode:
    :param pxe:
    :param raid_level:
    :param raid_phys_drives:
    :param logical_drive_noboot:
    :param init_storage_controller:
    :param hide_flexnics:
    :param server_id:
    :param hardware_type_name:
    :param bios_list:
    :param profile_template_name:
    :param kwargs:
    :return:
    '''
    result = {'success': False}

    if boot_order and disable_manage_boot:
        result['message'] = 'Managed boot must be enabled to define a boot order'
        return result

    srv = hpov.servers(hpeov_con)
    srv_type_settings = hpov.settings(hpeov_con)
    hardware_type = get_server_hardware_type_by_name(hardware_type_name)
    try:
        server, hwt = _get_server(hpeov_con, srv, server_id, hardware_type_name,
                                            force_power_off)
        boot, bootmode = _boot_settings(srv, hwt, disable_manage_boot,
                                        boot_order, boot_mode, pxe)
        local_storage = _local_storage_settings(hwt, raid_level,
                                               logical_drive_noboot, init_storage_controller,
                                               raid_phys_drives)
        fw_settings = _get_fw_settings(srv_type_settings, fw_baseline)
        bios = _bios_settings(bios_list)
        if profile_template_name:
            profile_template = get_server_profile_template_by_name(profile_template_name,
                                                                   host=host,
                                                                   username=username,
                                                                   password=password,
                                                                   domain=domain,
                                                                   **kwargs)

            profile_template_uri = profile_template['return']['uri']
            enclosure_group_uri = profile_template['return']['enclosureGroupUri']
        else:
            profile_template_uri = None

        if deployment_plan:
          plan = oneview_client.os_deployment_plans.get_by_name(deployment_plan)
          log.debug('--------------------------------------------')
          log.debug(plan)
          osdep_uri = plan['uri']

        ret = _define_profile_v3(oneview_client, name, profile_template_name, server['uri'], hwt['uri'], osdep_uri)
        result['return'] = ret
        result['success'] = True
    except HPOneViewException as e:
        result['message'] = format_hpov_exception(e)

    return result
