# -*- coding: utf-8 -*-
'''
    SaltStack Enterprise API Client
'''

# Import SSEApiClient libs
from sseapiclient._version import get_versions
from sseapiclient.apiclient import APIClient, RPCResponse

__version__ = get_versions()['version']
del get_versions
