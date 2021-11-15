# coding: utf-8
'''
    sseapiclient.tornado
    ~~~~~~~~~~~~~~~~~~~~

    Backward compatibility wrapper for sseapiclient. For new code, use the
    APIClient class.

    from sseapiclient import APIClient
    client = APIClient(server, username, ...)
'''

# Import SSEApiClient libs
from sseapiclient import APIClient
# pylint:disable=unused-import
from sseapiclient.exc import AuthenticationFailure, NotConnectable, RequestFailure, RPCError, TimeoutFailure

ClientDisconnected = NotConnectable
RPCCancelledError = TimeoutFailure
RPCTimeoutError = TimeoutFailure


class SyncClient(object):

    def __init__(self,
                 server,
                 username,
                 password=None,
                 config_name='internal',
                 pubkey_path=None,
                 loop=None,
                 cookies_path=None,
                 shared_jwt=None,
                 force_restfull=False,
                 use_jwt=True,
                 json_encoder=None,
                 max_message_size=None,
                 connect_timeout=5,
                 request_timeout=15,
                 ssl_ca=None,
                 ssl_key=None,
                 ssl_cert=None,
                 ssl_context=None,
                 ssl_validate_cert=True,
                 api_loader=None,
                 rpc_api_version=None):

        self._client = APIClient(server=server,
                                 username=username,
                                 password=password,
                                 config_name=config_name,
                                 timeout=max(connect_timeout or 0, request_timeout or 0, 60),
                                 use_jwt=use_jwt,
                                 shared_jwt=shared_jwt,
                                 pubkey_path=pubkey_path,
                                 cookies_path=cookies_path,
                                 json_encoder=json_encoder,
                                 rpc_api_version=rpc_api_version,
                                 api_loader=api_loader,
                                 ssl_key=ssl_key,
                                 ssl_cert=ssl_cert,
                                 ssl_validate_cert=ssl_validate_cert,
                                 ssl_context=ssl_context)

    @classmethod
    def connect(cls,
                server,
                username,
                password=None,
                config_name='internal',
                pubkey_path=None,
                loop=None,
                cookies_path=None,
                shared_jwt=None,
                force_restfull=False,
                use_jwt=True,
                json_encoder=None,
                max_message_size=None,
                connect_timeout=5,
                request_timeout=15,
                ssl_ca=None,
                ssl_key=None,
                ssl_cert=None,
                ssl_context=None,
                ssl_validate_cert=True,
                api_loader=None,
                rpc_api_version=None):

        return cls(server=server,
                   username=username,
                   password=password,
                   config_name=config_name,
                   pubkey_path=pubkey_path,
                   loop=loop,
                   cookies_path=cookies_path,
                   shared_jwt=shared_jwt,
                   force_restfull=force_restfull,
                   use_jwt=use_jwt,
                   json_encoder=json_encoder,
                   max_message_size=max_message_size,
                   connect_timeout=connect_timeout,
                   request_timeout=request_timeout,
                   ssl_ca=ssl_ca,
                   ssl_key=ssl_key,
                   ssl_cert=ssl_cert,
                   ssl_context=ssl_context,
                   ssl_validate_cert=ssl_validate_cert,
                   api_loader=api_loader,
                   rpc_api_version=rpc_api_version)

    def call(self, resource, method, *args, **kwargs):
        return self._client.call(resource, method, *args, **kwargs)

    def close(self):
        pass

    @property
    def last_auth_request_time(self):
        return self._client.last_auth_request_time

    @property
    def api(self):
        return self._client.api

    @property
    def api_versions(self):
        return self._client.api_versions

    @property
    def api_constants(self):
        return self._client.api_constants

    @property
    def api_errors(self):
        return self._client.api_errors
