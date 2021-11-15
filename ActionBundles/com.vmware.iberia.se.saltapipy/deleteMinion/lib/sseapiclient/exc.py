# -*- coding: utf-8 -*-
'''
    sseapiclient.exc
    ~~~~~~~~~~~~~~~~

    SaltStack Enterprise API Client Exceptions
'''


class BaseSSEApiException(Exception):
    '''
    Base class for all SSEApi exceptions
    '''
    pass  # pylint: disable=unnecessary-pass


class NotConnectable(BaseSSEApiException):
    '''
    Exception raised when the connection to the SSE server fails (no RPC call
    was made)
    '''
    def __init__(self, message=None):
        super(NotConnectable, self).__init__()
        self.message = message

    def __str__(self):
        return str(self.message)


class AuthenticationFailure(NotConnectable):
    '''
    Exception raised when authentication fails
    '''
    pass  # pylint: disable=unnecessary-pass


class TimeoutFailure(NotConnectable):
    '''
    Exception raised on timed out requests
    '''
    pass  # pylint: disable=unnecessary-pass


class RequestFailure(NotConnectable):
    '''
    Exception raised on failed requests (http errors)
    '''
    def __init__(self, code, message):
        super(RequestFailure, self).__init__()
        self.code = code
        self.message = message

    def __str__(self):
        return '{} {}'.format(self.code, self.message)


class RPCError(BaseSSEApiException):
    '''
    Exception raised when an error is received in an RPC return payload
    '''
    def __init__(self, code, message=None, detail=None):
        super(RPCError, self).__init__()
        self.code = code
        self.message = message
        self.detail = detail

    def __str__(self):
        if self.detail:
            formatted_text = '{0}: {1}\n'.format(self.code, self.message)
            formatted_text += self._format_errors(self.detail)
            return str(formatted_text)
        return str(self.message)

    def _format_errors(self, errors, indent=2):
        formatted_text = ''
        if isinstance(errors, list):
            for error in errors:
                if not isinstance(error, str):
                    error = str(error)
                formatted_text += ' ' * indent + '- ' + error + '\n'
        elif isinstance(errors, dict):
            for key in errors:
                formatted_text += ' ' * indent + key + ':\n'
                formatted_text += self._format_errors(errors[key], indent + 2)
        else:
            if not isinstance(errors, str):
                errors = str(errors)
            formatted_text += ' ' * indent + '- ' + errors + '\n'
        return formatted_text
