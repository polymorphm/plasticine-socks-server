# -*- mode: python; coding: utf-8 -*-
#
# Copyright (c) 2014 Andrej Antonov <polymorphm@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

assert str is not bytes

import functools
import asyncio
import datetime
from urllib import request as url_request
from urllib import parse as url_parse
import json
import socket
from .. import socks_server

ADDRINFO_APPSPOT_URL = 'https://addrinfo.appspot.com/'
REQUEST_TIMEOUT = 5.0
REQUEST_LIMIT = 1000000
CACHE_LEN = 1000
CACHE_EXPIRE = datetime.timedelta(hours=10)

@asyncio.coroutine
def init_hook(hook_environ, socks_server_environ, hook_args):
    loop = hook_args['loop']
    hook_environ['loop'] = loop
    assert loop is not None

def cache_put(cache, cache_keys, key, value):
    try:
        del cache[key]
    except KeyError:
        pass
    else:
        cache_keys.remove(key)
    
    cache[key] = {
            'time': datetime.datetime.utcnow(),
            'value': value,
            }
    cache_keys.append(key)
    
    while len(cache) > CACHE_LEN:
        extra_key = cache_keys[0]
        del cache[extra_key]
        cache_keys.remove(extra_key)

def cache_get(cache, cache_keys, key):
    try:
        cache_item = cache[key]
    except KeyError:
        return
    
    time_now = datetime.datetime.utcnow()
    time = cache_item['time']
    value = cache_item['value']
    
    if time > time_now or time + CACHE_EXPIRE < time_now:
        del cache[key]
        cache_keys.remove(key)
        return
    
    return value

@asyncio.coroutine
def remote_connection_hook(hook_environ, socks_server_environ, hook_args):
    remote_addr_type = hook_args['remote_addr_type']
    remote_addr = hook_args['remote_addr']
    remote_port = hook_args['remote_port']
    
    loop = hook_environ['loop']
    addrinfo_cache = hook_environ['addrinfo_cache']
    addrinfo_cache_keys = hook_environ['addrinfo_cache_keys']
    assert loop is not None
    
    def addrinfo_request():
        data = None
        error = None
        try:
            opener = url_request.build_opener()
            res = opener.open(
                    url_request.Request(
                            '{}?{}'.format(
                                    ADDRINFO_APPSPOT_URL,
                                    url_parse.urlencode({
                                            'host': remote_addr,
                                            }),
                                    ),
                            ),
                    timeout=REQUEST_TIMEOUT,
                    )
            data = res.read(REQUEST_LIMIT).decode(errors='replace')
            data = json.loads(data)
        except Exception as e:
            error = type(e), str(e)
        return data, error
    
    addr_list = cache_get(addrinfo_cache, addrinfo_cache_keys, remote_addr)
    
    if addr_list is None:
        print('*** {!r}: NOT in cache ***'.format(remote_addr))
        
        for try_i in range(3):
            data, error = yield from loop.run_in_executor(None, addrinfo_request)
            if not error:
                break
        
        if error or not isinstance(data, (tuple, list)):
            return
        
        first_addr_list = []
        second_addr_list = []
        
        for addrinfo_data in data:
            if not isinstance(addrinfo_data, (tuple, list)) and \
                    len(addrinfo_data) != 2:
                return
            
            family_str, addr = addrinfo_data
            
            if not isinstance(family_str, str) or not isinstance(addr, str):
                return
            
            if family_str == 'AF_INET6':
                first_addr_list.append(addr)
            if family_str == 'AF_INET':
                second_addr_list.append(addr)
        
        addr_list = first_addr_list + second_addr_list
        
        cache_put(addrinfo_cache, addrinfo_cache_keys, remote_addr, addr_list)
    else:
        print('*** {!r}: in cache ***'.format(remote_addr))
    
    for addr in addr_list:
        try:
            remote_reader, remote_writer = yield from asyncio.open_connection(
                    host=addr, port=remote_port,
                    limit=socks_server.READER_LIMIT, loop=loop)
        except OSError:
            continue
        
        remote_writer.get_extra_info('socket').setsockopt(
                socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        return remote_reader, remote_writer

def socks_server_create_feature():
    hook_environ = {
            'loop': None,
            'addrinfo_cache': {},
            'addrinfo_cache_keys': [],
            }
    
    return {
            'init_hook': functools.partial(init_hook, hook_environ),
            'remote_connection_hook': functools.partial(remote_connection_hook, hook_environ),
            }
