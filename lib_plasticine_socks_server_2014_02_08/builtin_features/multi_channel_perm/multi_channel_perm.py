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

import sys
import os, os.path
import weakref
import time
import functools
import asyncio
import signal
import socket
import struct
from lib_plasticine_socks_server_2014_02_08 import config_import
from lib_plasticine_socks_server_2014_02_08 import socks_server

def to_ipv6_str(ip_str):
    assert isinstance(ip_str, str)
    
    try:
        socket.inet_pton(socket.AF_INET6, ip_str)
    except OSError:
        pass
    else:
        return ip_str
    
    try:
        ipv4_bytes = socket.inet_pton(socket.AF_INET, ip_str)
    except OSError:
        pass
    else:
        ipv4_str = socket.inet_ntop(socket.AF_INET, ipv4_bytes)
        ipv6_str = '::ffff:{}'.format(ipv4_str)
        
        return ipv6_str
    
    raise ValueError('invalid IP format: {!r}'.format(ip_str))

def blocking_perm_load(hook_environ):
    user_list = []
    socks_list = []
    perm_list = []
    
    def show_syntax_error(perm_key, perm_value):
        try:
            print(
                    'WARNING: syntax error in config line {!r}'.format(
                            '{} = {}'.format(perm_key, perm_value),
                            ),
                    file=sys.stderr,
                    )
        except OSError:
            pass
    
    clean_split = lambda s, sep: tuple(filter(None, map(
            lambda s: s.strip(),
            s.split(sep=sep)
            )))
    
    one_clean_lsplit = lambda s, sep: tuple(filter(None, map(
            lambda s: s.strip(),
            s.split(sep=sep, maxsplit=1)
            )))
    
    one_clean_rsplit = lambda s, sep: tuple(filter(None, map(
            lambda s: s.strip(),
            s.rsplit(sep=sep, maxsplit=1)
            )))
    
    config_path = hook_environ['config_path']
    config_section = hook_environ['config_section']
    config = config_import.config_import(config_path)
    perm_config = config[config_section]
    
    for perm_key in perm_config:
        perm_value = perm_config[perm_key]
        
        if perm_key.startswith('user_'):
            perm_value_split = clean_split(perm_value, ';')
            
            if len(perm_value_split) != 3:
                show_syntax_error(perm_key, perm_value)
                continue
            
            user_symbol = perm_key
            username, password, perm_symbol = perm_value_split
            
            user_list.append((user_symbol, username, password, perm_symbol))
            
            continue
        
        if perm_key.startswith('socks_'):
            perm_value_split = one_clean_lsplit(perm_value, ';')
            
            if len(perm_value_split) != 2:
                show_syntax_error(perm_key, perm_value)
                continue
            
            socks_symbol = perm_key
            listen_addr_str, exit_list_str = perm_value_split
            
            listen_addr = one_clean_rsplit(listen_addr_str, ':')
            exit_list = clean_split(exit_list_str, ';')
            
            if len(listen_addr) != 2:
                show_syntax_error(perm_key, perm_value)
                continue
            
            try:
                listen_addr = to_ipv6_str(listen_addr[0]), int(listen_addr[1])
            except ValueError:
                show_syntax_error(perm_key, perm_value)
                continue
            
            socks_list.append((socks_symbol, listen_addr, exit_list))
            
            continue
        
        if perm_key.startswith('perm_'):
            perm_value_split = clean_split(perm_value, ';')
            
            perm_symbol = perm_key
            socks_symbol_list = perm_value_split
            
            perm_list.append((perm_symbol, socks_symbol_list))
            
            continue
    
    # optimization map for get exit_list
    exit_list_optim_map = {}
    
    for socks_symbol, listen_addr, exit_list in socks_list:
        for perm_symbol, perm_socks_symbol_list in perm_list:
            if '*' not in perm_socks_symbol_list and socks_symbol not in perm_socks_symbol_list:
                continue
            
            for user_symbol, username, password, user_perm_symbol in user_list:
                if user_perm_symbol not in perm_symbol:
                    continue
                
                if username == '*':
                    username = ''
                
                if password == '*':
                    password = ''
                
                exit_list_optim_map[(
                        socket.inet_pton(socket.AF_INET6, listen_addr[0]),
                        listen_addr[1],
                        username.encode(),
                        password.encode(),
                        )] = exit_list
    
    return {
            'user_list': tuple(user_list),
            'socks_list': tuple(socks_list),
            'perm_list': tuple(perm_list),
            'exit_list_optim_map': exit_list_optim_map,
            }

@asyncio.coroutine
def async_perm_load(hook_environ):
    loop = hook_environ['loop']
    assert loop is not None
    
    perm_cache = yield from loop.run_in_executor(None, blocking_perm_load, hook_environ)
    
    return perm_cache

@asyncio.coroutine
def perm_cache_refresh(hook_environ):
    loop = hook_environ['loop']
    assert loop is not None
    
    old_perm_cache = hook_environ['perm_cache']
    
    new_perm_cache = yield from async_perm_load(hook_environ)
    
    if old_perm_cache is hook_environ['perm_cache']:
        # set new value -- only if old value is not changed
        hook_environ['perm_cache'] = new_perm_cache

@asyncio.coroutine
def perm_check(hook_environ, client_writer, username_bytes, password_bytes):
    loop = hook_environ['loop']
    assert loop is not None
    
    perm_cache = hook_environ['perm_cache']
    exit_list_optim_map = perm_cache['exit_list_optim_map']
    
    exit_list = exit_list_optim_map.get((
            socket.inet_pton(socket.AF_INET6, client_writer.get_extra_info('sockname')[0]),
            client_writer.get_extra_info('sockname')[1],
            username_bytes,
            password_bytes,
            ))
    
    if exit_list is None:
        False, None
    
    return True, {
            'exit_list': exit_list,
            }

def read_config_hook(hook_environ, hook_args):
    config = hook_args['config']
    config_path = hook_args['config_path']
    config_section = hook_args['config_section']
    
    hook_environ['config_path'] = config_path
    hook_environ['config_section'] = config_section

def create_socks_sock_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 3
    unix = hook_args['unix']
    
    hook_environ['perm_cache'] = perm_cache = blocking_perm_load(hook_environ)
    
    socks_sock_list = []
    
    for socks_symbol, (listen_hostname, listen_port), exit_list in perm_cache['socks_list']:
        socks_sock = socket.socket(socket.AF_INET6)
        
        if hasattr(socket, 'SO_REUSEADDR'):
            try:
                socks_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                # SO_REUSEADDR is nice, but not required
                pass
        
        socks_sock.bind((listen_hostname, listen_port))
        
        socks_sock_list.append(socks_sock)
    
    return tuple(socks_sock_list)

@asyncio.coroutine
def init_hook(hook_environ, socks_server_environ, hook_args):
    loop = hook_args['loop']
    
    hook_environ['loop'] = loop
    assert loop is not None
    
    def usr_handler():
        asyncio.async(perm_cache_refresh(hook_environ), loop=loop)
    
    if hasattr(signal, 'SIGUSR1'):
        try:
            loop.add_signal_handler(signal.SIGUSR1, usr_handler)
        except NotImplementedError:
            pass
    
    if hasattr(signal, 'SIGUSR2'):
        try:
            loop.add_signal_handler(signal.SIGUSR2, usr_handler)
        except NotImplementedError:
            pass

@asyncio.coroutine
def auth_handle_hook(hook_environ, socks_server_environ, hook_args):
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    try:
        recv_data = yield from client_reader.readexactly(1)
    except (EOFError, OSError):
        return False
    
    recv_data = struct.unpack('!B', recv_data)
    
    if recv_data[0] != 0x05:
        # invalid SOCKS version
        
        return False
    
    try:
        recv_data = yield from client_reader.readexactly(1)
    except (EOFError, OSError):
        return False
    
    recv_data = struct.unpack('!B', recv_data)
    
    auth_count = recv_data[0]
    
    if auth_count < 1:
        # invalid number of authentication methods supported
        
        return False
    
    use_no_auth = False
    use_pass_auth = False
    
    for i in range(auth_count):
        try:
            recv_data = yield from client_reader.readexactly(1)
        except (EOFError, OSError):
            return False
        
        recv_data = struct.unpack('!B', recv_data)
        
        if recv_data[0] == 0x00:
            use_no_auth = True
        if recv_data[0] == 0x02:
            use_pass_auth = True
    
    if not use_no_auth and not use_pass_auth:
        client_writer.write(struct.pack(
                '!BB',
                0x05, # SOCKS version number (must be 0x05 for this version)
                0xff, # no acceptable methods were offered
                ))
        return False
    
    if use_pass_auth:
        client_writer.write(struct.pack(
                '!BB',
                0x05, # SOCKS version number (must be 0x05 for this version)
                0x02, # authentication method: username/password authentication (RFC 1929)
                ))
        
        try:
            recv_data = yield from client_reader.readexactly(1)
        except (EOFError, OSError):
            return False
        
        recv_data = struct.unpack('!B', recv_data)
        
        if recv_data[0] != 0x01:
            # invalid version of the subnegotiation
            
            return False
        
        try:
            recv_data = yield from client_reader.readexactly(1)
        except (EOFError, OSError):
            return False
        
        recv_data = struct.unpack('!B', recv_data)
        username_len = recv_data[0]
        
        try:
            recv_data = yield from client_reader.readexactly(username_len)
        except (EOFError, OSError):
            return False
        
        username_bytes = recv_data
        
        try:
            recv_data = yield from client_reader.readexactly(1)
        except (EOFError, OSError):
            return False
        
        recv_data = struct.unpack('!B', recv_data)
        password_len = recv_data[0]
        
        try:
            recv_data = yield from client_reader.readexactly(password_len)
        except (EOFError, OSError):
            return False
        
        password_bytes = recv_data
        
        is_allowed, client_data = yield from perm_check(
                hook_environ, client_writer, username_bytes, password_bytes,
                )
        
        if not is_allowed:
            client_writer.write(struct.pack(
                    '!BB',
                    0x01, # version of the subnegotiation
                    0xff, # fail
                    ))
            
            return False
        
        client_writer.write(struct.pack(
                '!BB',
                0x01, # version of the subnegotiation
                0x00, # success
                ))
    else:
        username_bytes = b''
        password_bytes = b''
        
        is_allowed, client_data = yield from perm_check(
                hook_environ, client_writer, username_bytes, password_bytes,
                )
        
        if not is_allowed:
            client_writer.write(struct.pack(
                    '!BB',
                    0x05, # SOCKS version number (must be 0x05 for this version)
                    0xff, # no acceptable methods were offered
                    ))
            return False
        
        client_writer.write(struct.pack(
                '!BB',
                0x05, # SOCKS version number (must be 0x05 for this version)
                0x00, # authentication method: no authentication
                ))
    
    hook_environ['client_map'][client_writer] = client_data
    
    return True

@asyncio.coroutine
def remote_connection_hook(hook_environ, socks_server_environ, hook_args):
    client_writer = hook_args['client_writer']
    remote_addr_type = hook_args['remote_addr_type']
    remote_addr = hook_args['remote_addr']
    remote_port = hook_args['remote_port']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    client_data = hook_environ['client_map'][client_writer]
    exit_list = client_data['exit_list']
    
    for exit_hostname in exit_list:
        family = None
        
        try:
            socket.inet_pton(socket.AF_INET6, exit_hostname)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET, exit_hostname)
            except OSError:
                return False
            else:
                family = socket.AF_INET
        else:
            family = socket.AF_INET6
        
        #print('*** {} (family {!r}) -> {} (port {}): connection...***'.format(exit_hostname, family, remote_addr, remote_port))
        
        try:
            remote_reader, remote_writer = yield from asyncio.open_connection(
                    host=remote_addr, port=remote_port,
                    limit=socks_server.READER_LIMIT, loop=loop,
                    family=family, local_addr=(exit_hostname, 0),
                    )
        except OSError:
            #print('*** {} (family {!r}) -> {} (port {}): connection fail ***'.format(exit_hostname, family, remote_addr, remote_port))
            
            continue
        else:
            break
    else:
        return False
    
    remote_writer.get_extra_info('socket').setsockopt(
            socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    
    #print('*** {} (family {!r}) -> {} (port {}): connection success ***'.format(exit_hostname, family, remote_addr, remote_port))
    
    return remote_reader, remote_writer

def socks_server_create_feature():
    hook_environ = {
            'loop': None,
            'client_map': weakref.WeakKeyDictionary(),
            'config_path': None,
            'config_section': None,
            'perm_cache': None,
            }
    
    return {
            'read_config_hook': functools.partial(read_config_hook, hook_environ),
            'create_socks_sock_hook': functools.partial(create_socks_sock_hook, hook_environ),
            'init_hook': functools.partial(init_hook, hook_environ),
            'auth_handle_hook': functools.partial(auth_handle_hook, hook_environ),
            'remote_connection_hook': functools.partial(remote_connection_hook, hook_environ),
            }