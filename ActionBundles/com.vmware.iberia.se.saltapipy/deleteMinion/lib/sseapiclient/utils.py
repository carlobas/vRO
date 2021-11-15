# -*- coding: utf-8 -*-
'''
    sseapiclient.utils
    ~~~~~~~~~~~~~~~~~~

    sseapi-client utilities
'''

# Import Python libs
from __future__ import absolute_import, print_function
from collections import namedtuple


def truncate_string(string, max_length=1000, truncate_comment=None):
    '''
    Truncate the middle of a string if longer than the provided `max_length` inserting a
    commend instead stating that the string is a truncated version of a longer string.
    An effort is made to make sure the left and right strings end and start respectively
    on a found white-space character.
    '''
    if not isinstance(string, str):
        string = str(string)

    # Remove leading and trailing white-space
    string = string.strip()

    if truncate_comment is None:
        truncate_comment = '[ ... truncated for size ... ]'

    truncated_string_nt = namedtuple('TruncatedString', ['truncated', 'full', 'short'])
    if len(string) <= max_length:
        return truncated_string_nt(False, string, string)

    return truncated_string_nt(True, string, truncate_comment + ' ' + string[:max_length])

#    half_max_length = int(max_length//2)
#    extra_search_chars = 50
#    left_whitespace_index = string[:half_max_length + extra_search_chars].rfind(' ')
#    if not left_whitespace_index:
#        left_whitespace_index = half_max_length
#    left_string = string[:left_whitespace_index].strip()
#
#    if truncate_comment is None:
#        truncate_comment = '[ ... truncated for size ... ]'
#
#    right_whitespace_index = string.find(' ', len(string) - half_max_length - extra_search_chars)
#    if not right_whitespace_index:
#        right_whitespace_index = half_max_length
#    else:
#        right_whitespace_index += 1  # without the actual white-space char
#    right_string = string[right_whitespace_index:].strip()
#
#    short_string = '{0} {1} {2}'.format(left_string, truncate_comment, right_string)
#    return truncated_string_nt(True, string, short_string)
