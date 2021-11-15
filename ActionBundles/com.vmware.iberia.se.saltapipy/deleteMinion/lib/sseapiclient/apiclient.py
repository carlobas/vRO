# coding: utf-8

import base64
import copy
import logging
import sys
from collections import namedtuple
from operator import itemgetter

# Import SSEApiClient libs
import sseapiclient.apiloader
import sseapiclient.httpclient
from sseapiclient.exc import RPCError
from sseapiclient.utils import truncate_string

try:
    import salt.ext.six as six
except ImportError:
    import six


log = logging.getLogger(__name__)


class RPCResponse(namedtuple('RPCResponse', ['riq', 'ret', 'error', 'warnings'])):
    '''
    Namedtuple class to hold the RPC response details
    '''
    __slots__ = ()

    def __new__(cls, riq, ret=None, error=None, warnings=None):  # pylint: disable=too-many-arguments
        return super(RPCResponse, cls).__new__(cls, riq, ret, error, warnings or [])

    riq = property(itemgetter(0), doc='The RPC request ID')
    ret = property(itemgetter(1), doc='The RPC request return data')
    error = property(itemgetter(2), doc='The RPC request error, if any')
    warnings = property(itemgetter(3), doc='The RPC request warnings, if any')

    @staticmethod
    def from_response_dict(response):
        return RPCResponse(
            response['riq'],
            response['ret'],
            response['error'],
            response['warnings'],
        )


class APIClient(object):
    '''
    A synchronous client for use with the SaltStack Enterprise API
    '''
    def __init__(self,
                 server,
                 username,
                 password=None,
                 config_name='internal',
                 timeout=60,
                 use_jwt=True,
                 shared_jwt=None,
                 pubkey_path=None,
                 cookies_path=None,
                 json_encoder=None,
                 rpc_api_version=None,
                 api_loader=None,
                 ssl_key=None,
                 ssl_cert=None,
                 ssl_validate_cert=True,
                 ssl_context=None):
        self.httpclient = sseapiclient.httpclient.HTTPClient(server=server,
                                                             username=username,
                                                             password=password,
                                                             config_name=config_name,
                                                             timeout=timeout,
                                                             use_jwt=use_jwt,
                                                             shared_jwt=shared_jwt,
                                                             pubkey_path=pubkey_path,
                                                             cookies_path=cookies_path,
                                                             json_encoder=json_encoder,
                                                             rpc_api_version=rpc_api_version,
                                                             ssl_key=ssl_key,
                                                             ssl_cert=ssl_cert,
                                                             ssl_validate_cert=ssl_validate_cert,
                                                             ssl_context=ssl_context)
        self._discovered = False
        self._current_riq = 0
        self._api = None
        self._api_versions = None
        self._discovered_api = None
        self._discovered_constants = None
        self._discovered_errors = None
        if api_loader is None:
            if hasattr(sys, 'ps1'):
                # Are we running in an interactive shell?
                api_loader = sseapiclient.apiloader.InteractiveApiLoader
            else:
                api_loader = sseapiclient.apiloader.ApiWrapper
        self._api_loader = api_loader
        self.discover()

    def __repr__(self):
        return '<{cls} {desc}>'.format(cls=self.__class__.__name__, desc=self.httpclient.describe())

    def discover(self):
        if not self._discovered:
            log.info('Discovering API')
            result = self.call(resource='api', method='get_versions')
            self._api_versions = result.ret
            result = self.call(resource='api', method='discover')
            self._discovered_api = result.ret['api']
            self._discovered_constants = result.ret['constants']
            self._rpc_api_version = self._discovered_constants['rpc-api-version']
            self.httpclient.rpc_api_version = self._rpc_api_version
            self._discovered_errors = result.ret['errors']
            self._discovered = True
        return self._discovered

    def next_request_id(self):
        self._current_riq += 1
        return self._current_riq

    @property
    def api(self):
        if self._api is None:
            self._api = self._api_loader(self)
        return self._api

    @property
    def rpc_api_version(self):
        return self._rpc_api_version

    @property
    def api_versions(self):
        if not self._discovered:
            return '<not discovered yet>'
        return self._api_versions

    @property
    def api_constants(self):
        if not self._discovered:
            return '<not discovered yet>'
        return self._discovered_constants

    @property
    def api_errors(self):
        if not self._discovered:
            return '<not discovered yet>'
        rpc_internal_server_error_code = 5000
        if rpc_internal_server_error_code not in self._discovered_errors['errorcode']:
            errorcode = self._discovered_errors['errorcode']
            # JSON only allows dictionary keys to be strings.
            # Covert the error codes keys to integers
            for errno in errorcode.copy():
                errorcode[int(errno)] = errorcode.pop(errno)
        return self._discovered_errors

    @property
    def last_auth_request_time(self):
        if self.httpclient is not None:
            return self.httpclient.last_auth_request_time
        return 0

    def get_lock(self, lock_name):
        response = self.httpclient.get_lock(lock_name)
        return response['ret']

    def request_master_key(self, master_id):
        return self.httpclient.request_master_key(master_id)

    def get_master_jwt(self, test=False, init_xsrf=False):
        return self.httpclient.get_master_jwt(test=test, init_xsrf=init_xsrf)

    def call(self, resource, method, *args, **kwargs):
        riq = kwargs.pop('riq', None) or self.next_request_id()
        timeout = kwargs.pop('timeout', None)
        log.info('Calling API %s.%s', resource, method)
        log.debug('Full API call: %s.%s(%s, %s)', resource, method,
                 truncate_string(args).short, truncate_string(kwargs).short)
        args, kwargs = self.pre_process_call(resource, method, *args, **kwargs)

        payload = {'riq': riq,
                   'resource': resource,
                   'method': method,
                   'args': args,
                   'kwargs': kwargs}

        result = self.httpclient.fetch(url='/rpc', method='POST', body=payload, timeout=timeout)
        try:
            if result['error']:
                raise RPCError(code=result['error']['code'],
                               message=result['error']['message'],
                               detail=result['error'].get('detail'))
            for warning in result['warnings']:
                log.warning('riq %s: %s.%s: %s', riq, resource, method, warning)

            result = self.post_process_call(resource, method, result)
            return RPCResponse.from_response_dict(result)
        except (AttributeError, KeyError, TypeError):
            return RPCResponse(riq=riq, ret=result)

    def call_many(self, calls, timeout=None):
        '''
        Make several RPC API calls in a single request to the SSE server.

        The `calls` parameter is a list of objects each with these elements:
            - riq (request id, optional)
            - resource (resource name)
            - method (method name)
            - args (positional arguments, optional)
            - kwargs (keyword arguments, optional)

        The `timeout` value applies to all the calls together.

        The return value is a list of `RPCResponse` objects, one for each RPC
        call, in the same order as the original call payloads.
        '''
        payloads = []
        for call in calls:
            riq = call.get('riq') or self.next_request_id()
            resource = call['resource']
            method = call['method']
            args = call.get('args') or call.get('arg') or []
            kwargs = call.get('kwargs') or call.get('kwarg') or {}
            args, kwargs = self.pre_process_call(resource, method, *args, **kwargs)
            log.info('Calling API %s.%s', resource, method)
            log.debug('Full API call: %s.%s(%s, %s)', resource, method,
                    truncate_string(args).short, truncate_string(kwargs).short)
            payload = {'riq': riq, 'resource': resource, 'method': method, 'args': args, 'kwargs': kwargs}
            payloads.append(payload)

        results = self.httpclient.fetch(url='/rpc', method='POST', body=payloads, timeout=timeout)

        rets = []
        for idx, result in enumerate(results['ret']):
            payload = payloads[idx]
            try:
                if result['error']:
                    msg = 'riq {}: {}.{}: code {}: {}'.format(
                            result['riq'],
                            payload['resource'], payload['method'],
                            result['error']['code'], result['error']['message'])
                    if 'detail' in result['error']:
                        msg += ' (detail: {})'.format(result['error']['detail'])
                    log.error(msg)
                for warning in result['warnings']:
                    msg = 'riq {}: {}.{}: {}'.format(
                            result['riq'],
                            payload['resource'], payload['method'],
                            warning)
                    log.warning(msg)
                result = self.post_process_call(resource, method, result)
                ret = RPCResponse.from_response_dict(result)
            except (AttributeError, KeyError, TypeError):
                response = RPCResponse(riq=payload['riq'], ret=result)
            rets.append(ret)

        return {
            'batched_retcode': results['batched_retcode'],
            'ret': rets
        }

    def pre_process_call(self, resource, method, *args, **kwargs):
        if resource == 'fs' and method == 'save_file':
            content_type = kwargs.get('content_type', None)
            if content_type is None or not content_type.startswith('text/'):
                data = copy.deepcopy(kwargs['contents'])
                if six.PY3:
                    if not isinstance(data, bytes):
                        data = bytes(data, 'utf-8')
                    data = ''.join(base64.encodebytes(data).decode('utf-8').strip().split('\n'))
                else:
                    data = ''.join(base64.encodestring(data).strip().split('\n'))  # pylint: disable=deprecated-method
                kwargs['contents'] = data
        return args, kwargs

    def post_process_call(self, resource, method, result):
        if resource == 'fs' and method == 'get_file':
            content_type = result['ret'].get('content_type', None)
            if content_type is None or not content_type.startswith('text/'):
                if six.PY3:
                    result['ret']['contents'] = base64.decodebytes(result['ret']['contents'].encode('utf-8'))
                else:
                    result['ret']['contents'] = base64.decodestring(result['ret']['contents'])  # pylint: disable=deprecated-method
        return result
