# -*- coding: utf-8 -*-
'''
    sseapiclient.apiloader
    ~~~~~~~~~~~~~~~~~~~~~~

    Simple API resolution wrapper classes
'''

# Import Python libs
from __future__ import absolute_import
import types
import weakref

try:
    import textwrap
    textwrap.indent  # pylint: disable=pointless-statement
except AttributeError:  # undefined function (wasn't added until Python 3.3)
    def indent(text, amount, char=' '):
        padding = amount * char
        return ''.join(padding+line for line in text.splitlines(True))
else:
    def indent(text, amount, char=' '):
        return textwrap.indent(text, amount * char)

try:
    import salt.ext.six as six
except ImportError:
    import six


class Method(object):

    __slots__ = ('_client_ref', '_resource_name', '_method_name')

    def __init__(self, client_ref, resource_name, method_name):
        self._client_ref = client_ref
        self._resource_name = resource_name
        self._method_name = method_name

    def __call__(self, *args, **kwargs):
        return self._client_ref().call(self._resource_name, self._method_name, *args, **kwargs)


class Resource(object):

    __slots__ = ('_client_ref', '_resource_name', '_methods')

    def __init__(self, client_ref, resource_name):
        self._client_ref = client_ref
        self._resource_name = resource_name
        self._methods = {}

    def __getattribute__(self, name):
        if name in ('_client_ref', '_resource_name', '_methods'):
            return object.__getattribute__(self, name)
        if name not in self._methods:
            self._methods[name] = Method(self._client_ref, self._resource_name, name)
        return self._methods[name]


class ApiWrapper(object):

    __slots__ = ('_client_ref', '_resources')

    def __init__(self, client):
        self._client_ref = weakref.ref(client)
        self._resources = {}

    def __getattribute__(self, name):
        if name in ('_client_ref', '_resources'):
            return object.__getattribute__(self, name)
        if name not in self._resources:
            self._resources[name] = Resource(self._client_ref, name)
        return self._resources[name]


class InteractiveApiLoader(object):
    __requires_api_docs__ = True

    def __new__(cls, client):
        client_attrs = {
            '__requires_api_docs__': True,
            '__doc__': 'SSEApiClient RPC Api',
            '_client': client
        }
        for resource_name in client._discovered_api:
            if six.PY2:
                resource_name = str(resource_name)
            instance_attrs = {'_client': client}

            resource_doc = client._discovered_api[resource_name].get('__doc__', None)
            if resource_doc:
                instance_attrs['__doc__'] = resource_doc

            for method_name in client._discovered_api[resource_name]:
                if method_name == '__doc__':
                    continue
                instance_attrs[method_name] = None

            resource_instance = type(resource_name, (object,), instance_attrs)
            for method_name in instance_attrs:
                if method_name in ('__doc__', '_client'):
                    continue
                func_def = textwrap.dedent('''\
                def {funcname}({params}):
                    """
                {funcdoc}
                    """
                    return self._client.call('{resource_name}', '{funcname}', {param_names})
                ''')
                exec_locals = {}
                exec_globals = {}
                func_params = client._discovered_api[resource_name][method_name]['detailed'].get('parameters', None)
                params = ['self']
                param_names = []
                if func_params is None:
                    params.extend(['*args', '**kwargs'])
                    param_names.extend(['*args', '**kwargs'])
                else:
                    star_kwargs_found = False
                    for param in func_params:
                        if len(param) == 1:
                            if param == ['**kwargs']:
                                star_kwargs_found = True
                                continue
                            params.append(param[0])
                            param_names.append(param[0])
                        else:
                            params.append('{0}={1}'.format(param[0], repr(param[1])))
                            param_names.append('{0}={0}'.format(param[0]))
                    params.append('timeout=None')
                    param_names.append('timeout=timeout')
                    if star_kwargs_found:
                        params.append('**kwargs')
                        param_names.append('**kwargs')
                func_doc = '{0}\n\n{1}'.format(
                    client._discovered_api[resource_name][method_name]['detailed']['signature'],
                    client._discovered_api[resource_name][method_name]['detailed']['doc']
                )
                formatted_code = func_def.format(
                    funcname=method_name,
                    resource_name=resource_name,
                    params=', '.join(params),
                    param_names=', '.join(param_names),
                    funcdoc=indent(func_doc, 4),
                )
                # Create the function in the above exec locals and globals context
                exec(formatted_code, exec_globals, exec_locals)  # pylint: disable=exec-used
                # Bound the function to the resource_instance
                setattr(resource_instance,
                        method_name,
                        types.MethodType(exec_locals[method_name], resource_instance))
            client_attrs[resource_name] = resource_instance
        instance = type('api', (object,), client_attrs)
        return instance

    def __init__(self, client):
        self._client = client
