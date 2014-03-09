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

import importlib
import socket
import select
import os
import struct
import asyncio

SOCKET_BACKLOG = 100
REQUEST_TIMEOUT = 15.0
BUF_SIZE = 1000000

def preinit_socks_server(socks_server_environ, features=None):
    socks_server_environ['shutdown_event'] = asyncio.Event()
    socks_server_environ['loop'] = None
    socks_server_environ['socks_socket'] = None
    
    if features is None:
        features = ()
    
    socks_server_environ['features'] = features
    
    for feature in features:
        preinit_hook = feature.get('preinit_hook')
        if preinit_hook is not None:
            preinit_hook(socks_server_environ, {})

def create_socks_socket_socks_server(socks_server_environ, unix=None, ip=None, port=None):
    assert unix is None or isinstance(unix, str)
    assert ip is None or isinstance(ip, str)
    assert port is None or isinstance(port, int)
    
    if unix is None and port is None:
        port = 8080
    
    if unix is None and ip is None:
        ip = '::1'
    
    features = socks_server_environ['features']
    
    for feature in features:
        create_socks_socket_hook = feature.get('create_socks_socket_hook')
        if create_socks_socket_hook is not None:
            socks_socket = create_socks_socket_hook(socks_server_environ, {
                    'unix': unix,
                    'ip': ip,
                    'port': port,
                    })
            
            if socks_socket is not None:
                socks_server_environ['socks_socket'] = socks_socket
                return
    
    if unix is not None:
        unix_new_path = '{}.new-{}'.format(unix, os.getpid())
        socks_socket = socket.socket(socket.AF_UNIX)
        
        socks_socket.bind(unix_new_path)
        os.rename(unix_new_path, unix)
    else:
        assert isinstance(ip, str)
        assert isinstance(port, int)
        
        socks_socket = socket.socket(socket.AF_INET6)
        
        socks_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socks_socket.bind((ip, port))
    
    socks_socket.setblocking(False)
    socks_socket.listen(SOCKET_BACKLOG)
    
    socks_server_environ['socks_socket'] = socks_socket

def before_fork_socks_server(socks_server_environ):
    for feature in socks_server_environ['features']:
        before_fork_hook = feature.get('before_fork_hook')
        if before_fork_hook is not None:
            before_fork_hook(socks_server_environ, {})

def after_fork_socks_server(socks_server_environ):
    for feature in socks_server_environ['features']:
        after_fork_hook = feature.get('after_fork_hook')
        if after_fork_hook is not None:
            after_fork_hook(socks_server_environ, {})

@asyncio.coroutine
def shutdown_socks_server(socks_server_environ, loop):
    # XXX: shutdown may be executed before of execution init (or init completed)
    
    if socks_server_environ['loop'] is not None:
        loop = socks_server_environ['loop']
    else:
        socks_server_environ['loop'] = loop
    
    assert loop is socks_server_environ['loop'], \
            'shutdown-loop and init-loop must be same object'
    
    features = socks_server_environ['features']
    
    for feature in features:
        shutdown_hook = feature.get('shutdown_hook')
        if shutdown_hook is not None:
            yield from shutdown_hook(socks_server_environ, {'loop': loop})
    
    socks_server_environ['shutdown_event'].set()

@asyncio.coroutine
def init_socks_server(socks_server_environ, loop):
    features = socks_server_environ['features']
    socks_server_environ['loop'] = loop
    
    for feature in features:
        init_hook = feature.get('init_hook')
        if init_hook is not None:
            yield from init_hook(socks_server_environ, {'loop': loop})

@asyncio.coroutine
def conn_close_socks_server(socks_server_environ, conn, address):
    features = socks_server_environ['features']
    
    try:
        for feature in features:
            close_hook = feature.get('close_hook')
            if close_hook is not None:
                close_hook_result = yield from close_hook(socks_server_environ, {
                        'conn': conn,
                        'address': address,
                        })
    finally:
        conn.close()

@asyncio.coroutine
def _read_n_socks_server(socks_server_environ, conn, n):
    loop = socks_server_environ['loop']
    recv_data = b''
    
    while len(recv_data) < n:
        try:
            buf = yield from loop.sock_recv(conn, n - len(recv_data))
        except OSError:
            break
        
        if not buf:
            break
        
        recv_data += buf
    
    assert len(recv_data) <= n
    
    return recv_data

@asyncio.coroutine
def conn_auth_socks_server(socks_server_environ, conn, address):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    
    for feature in features:
        auth_handle_hook = feature.get('auth_handle_hook')
        if auth_handle_hook is not None:
            auth_handle_hook_result = yield from auth_handle_hook(socks_server_environ, {
                    'conn': conn,
                    'address': address,
                    })
            
            if auth_handle_hook_result is not None:
                assert isinstance(auth_handle_hook_result, bool)
                
                return auth_handle_hook_result
    
    recv_data = yield from _read_n_socks_server(socks_server_environ, conn, 1)
    
    if len(recv_data) != 1:
        return False
    
    recv_data = struct.unpack('!B', recv_data)
    
    if recv_data[0] != 0x05:
        # invalid SOCKS version
        
        return False
    
    recv_data = yield from _read_n_socks_server(socks_server_environ, conn, 1)
    
    if len(recv_data) != 1:
        return False
    
    recv_data = struct.unpack('!B', recv_data)
    
    auth_count = recv_data[0]
    
    if auth_count < 1:
        # invalid number of authentication methods supported
        
        return False
    
    use_no_auth = False
    
    for i in range(auth_count):
        recv_data = yield from _read_n_socks_server(socks_server_environ, conn, 1)
        
        if len(recv_data) != 1:
            return False
        
        recv_data = struct.unpack('!B', recv_data)
        
        if recv_data[0] == 0x00:
            use_no_auth = True
    
    if not use_no_auth:
        yield from loop.sock_sendall(conn, struct.pack(
                '!BB',
                0x05, # SOCKS version number (must be 0x05 for this version)
                0xff, # no acceptable methods were offered
                ))
        return False
    
    yield from loop.sock_sendall(conn, struct.pack(
            '!BB',
            0x05, # SOCKS version number (must be 0x05 for this version)
            0x00, # authentication method: no authentication
            ))
    
    return True

@asyncio.coroutine
def remote_conn_socks_server(
        socks_server_environ, conn, address,
        remote_addr_type, remote_addr, remote_port):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    is_allowed = True
    
    for feature in features:
        before_remote_conn_hook = feature.get('before_remote_conn_hook')
        if before_remote_conn_hook is not None:
            before_remote_conn_hook_result = yield from before_remote_conn_hook(
                    socks_server_environ, {
                            'conn': conn,
                            'address': address,
                            'remote_addr_type': remote_addr_type,
                            'remote_addr': remote_addr,
                            'remote_port': remote_port,
                            })
            
            if before_remote_conn_hook_result is not None:
                assert isinstance(before_remote_conn_hook_result, bool)
                
                is_allowed = before_remote_conn_hook_result
                
                if is_allowed:
                    # positive if at least one feature hook is positive
                    
                    break
    
    if not is_allowed:
        return
    
    for feature in features:
        remote_conn_hook = feature.get('remote_conn_hook')
        if remote_conn_hook is not None:
            remote_conn_hook_result = yield from remote_conn_hook(
                    socks_server_environ, {
                            'conn': conn,
                            'address': address,
                            'remote_addr_type': remote_addr_type,
                            'remote_addr': remote_addr,
                            'remote_port': remote_port,
                            })
            
            if remote_conn_hook_result is not None:
                if not remote_conn_hook_result:
                    # remote connection fail
                    
                    return
                
                remote_conn = remote_conn_hook_result
                # XXX expected remote_conn is ALREADY non-block and keepalive
                
                break
    else:
        try:
            addrinfo_list = yield from loop.getaddrinfo(
                    remote_addr, remote_port, proto=socket.SOL_TCP)
        except OSError:
            addrinfo_list = None
        
        if not addrinfo_list:
            return
        
        for addrinfo in addrinfo_list:
            assert len(addrinfo) == 5
            
            remote_conn = socket.socket(addrinfo[0], addrinfo[1], addrinfo[2])
            remote_conn.setblocking(False)
            remote_conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            try:
                yield from loop.sock_connect(remote_conn, addrinfo[4])
            except OSError:
                continue
            
            break
        else:
            return
    
    for feature in features:
        after_remote_conn_hook = feature.get('after_remote_conn_hook')
        if after_remote_conn_hook is not None:
            after_remote_conn_hook_result = yield from after_remote_conn_hook(
                    socks_server_environ, {
                            'conn': conn,
                            'address': address,
                            'remote_addr_type': remote_addr_type,
                            'remote_addr': remote_addr,
                            'remote_port': remote_port,
                            'remote_conn': remote_conn,
                            })
            
            if after_remote_conn_hook_result is not None:
                assert isinstance(after_remote_conn_hook_result, bool)
                
                is_allowed = after_remote_conn_hook_result
                
                if is_allowed:
                    # positive if at least one feature hook is positive
                    
                    break
    
    if not is_allowed:
        remote_conn.close()
        return
    
    return remote_conn

@asyncio.coroutine
def conn_handle_socks_server(socks_server_environ, conn, address):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    shutdown_event = socks_server_environ['shutdown_event']
    
    @asyncio.coroutine
    def shutdown_coro():
        yield from shutdown_event.wait()
        conn_handle_future.cancel()
    
    DEBUG_DATA = []
    @asyncio.coroutine
    def request_timeout_coro():
        yield from asyncio.sleep(REQUEST_TIMEOUT, loop=loop)
        conn_handle_future.cancel()
        print('*** {!r}: TIMEOUT {!r} ***'.format(address, DEBUG_DATA))
    
    @asyncio.coroutine
    def conn_handle_coro():
        print('*** {!r}: BEGIN ***'.format(address))
        DEBUG_DATA.append('BEGIN')
        
        auth_result = yield from conn_auth_socks_server(
                socks_server_environ, conn, address)
        
        assert isinstance(auth_result, bool)
        
        if not auth_result:
            return
        
        DEBUG_DATA.append('after auth')
        
        recv_data = yield from _read_n_socks_server(
                socks_server_environ, conn, 1)
        
        DEBUG_DATA.append('after read_n_... #1')
        
        if len(recv_data) != 1:
            return
        
        recv_data = struct.unpack('!B', recv_data)
        
        if recv_data[0] != 0x05:
            # invalid SOCKS version
            
            return
        
        recv_data = yield from _read_n_socks_server(
                socks_server_environ, conn, 1)
        
        DEBUG_DATA.append('after read_n_... #2')
        
        if len(recv_data) != 1:
            return
        
        cmd_code = recv_data[0]
        
        if cmd_code != 0x01:
            # command not supported or invalid
            
            return
        
        recv_data = yield from _read_n_socks_server(
                socks_server_environ, conn, 2)
        
        DEBUG_DATA.append('after read_n_... #3')
        
        if len(recv_data) != 2:
            return
        
        recv_data = struct.unpack('!BB', recv_data)
        
        remote_addr_type_code = recv_data[1]
        
        if remote_addr_type_code == 0x01:
            remote_addr_type = 'ipv4'
            remote_addr_bytes = yield from _read_n_socks_server(
                    socks_server_environ, conn, 4)
            
            if len(remote_addr_bytes) != 4:
                return
            
            remote_addr = socket.inet_ntop(socket.AF_INET, remote_addr_bytes)
        elif remote_addr_type_code == 0x03:
            remote_addr_type = 'domain'
            
            recv_data = yield from _read_n_socks_server(
                    socks_server_environ, conn, 1)
            
            if len(recv_data) != 1:
                return
            
            remote_addr_len = struct.unpack('!B', recv_data)[0]
            
            remote_addr_bytes = yield from _read_n_socks_server(
                    socks_server_environ, conn, remote_addr_len)
            
            if len(remote_addr_bytes) != remote_addr_len:
                return
            
            remote_addr = remote_addr_bytes.decode(errors='replace')
        elif remote_addr_type_code == 0x04:
            remote_addr_type = 'ipv6'
            remote_addr_bytes = yield from _read_n_socks_server(
                    socks_server_environ, conn, 16)
            
            if len(remote_addr_bytes) != 16:
                return
            
            remote_addr = socket.inet_ntop(socket.AF_INET6, remote_addr_bytes)
        else:
            # invalid address type
            
            return
        
        DEBUG_DATA.append('before read_n_... #222')
        
        recv_data = yield from _read_n_socks_server(
                socks_server_environ, conn, 2)
        
        DEBUG_DATA.append('after read_n_... #222')
        
        if len(recv_data) != 2:
            return
        
        remote_port = struct.unpack('!H', recv_data)[0]
        
        DEBUG_DATA.append('before connect')
        
        remote_conn = yield from remote_conn_socks_server(
                socks_server_environ, conn, address,
                remote_addr_type, remote_addr, remote_port)
        
        if remote_conn is None:
            yield from loop.sock_sendall(conn, struct.pack(
                    '!BB',
                    0x05, # SOCKS version number (must be 0x05 for this version)
                    0x04, # host unreachable
                    ))
            return
        
        DEBUG_DATA.append('after connect (success)')
        
        try:
            yield from loop.sock_sendall(conn, struct.pack(
                    '!BBBB',
                    0x05, # SOCKS version number (must be 0x05 for this version)
                    0x00, # request granted
                    0x00, # reserved, must be 0x00
                    0x04, # address type: IPv6
                    ))
            yield from loop.sock_sendall(conn, bytes(18)) # pseudo addr-and-port
            
            DEBUG_DATA.append('before cancel of timeout')
            
            request_timeout_future.cancel()
            
            def read_local_coro():
                while True:
                    try:
                        buf = yield from loop.sock_recv(conn, BUF_SIZE)
                    except OSError:
                        buf = ''
                    
                    for feature in features:
                        read_local_hook = feature.get('read_local_hook')
                        if read_local_hook is not None:
                            read_local_hook_result = yield from read_local_hook(socks_server_environ, {
                                    'conn': conn,
                                    'address': address,
                                    'remote_conn': remote_conn,
                                    'buf': buf,
                                    })
                            
                            if read_local_hook_result is not None:
                                assert isinstance(read_local_hook_result, bytes)
                                
                                buf = read_local_hook_result
                                
                                # XXX: if ``buf`` will is empty -- will be disconnection
                    
                    if not buf:
                        return
                    
                    yield from loop.sock_sendall(remote_conn, buf)
            
            def read_remote_coro():
                 while True:
                    try:
                        buf = yield from loop.sock_recv(remote_conn, BUF_SIZE)
                    except OSError:
                        buf = ''
                    
                    for feature in features:
                        read_remote_hook = feature.get('read_remote_hook')
                        if read_remote_hook is not None:
                            read_remote_hook_result = yield from read_remote_hook(socks_server_environ, {
                                    'conn': conn,
                                    'address': address,
                                    'remote_conn': remote_conn,
                                    'buf': buf,
                                    })
                            
                            if read_remote_hook_result is not None:
                                assert isinstance(read_remote_hook_result, bytes)
                                
                                buf = read_remote_hook_result
                                
                                # XXX: if ``buf`` will is empty -- will be disconnection
                    
                    if not buf:
                        return
                    
                    yield from loop.sock_sendall(conn, buf)
            
            read_local_future, read_remote_future = \
                    asyncio.async(read_local_coro(), loop=loop), \
                    asyncio.async(read_remote_coro(), loop=loop)
            try:
                yield from asyncio.wait(
                        (read_local_future, read_remote_future),
                        loop=loop,
                        return_when=asyncio.FIRST_COMPLETED,
                        )
            finally:
                read_local_future.cancel()
                read_remote_future.cancel()
        finally:
            remote_conn.close()
    
    shutdown_future, request_timeout_future, conn_handle_future = \
            asyncio.async(shutdown_coro(), loop=loop), \
            asyncio.async(request_timeout_coro(), loop=loop), \
            asyncio.async(conn_handle_coro(), loop=loop)
    try:
        yield from asyncio.wait((conn_handle_future,), loop=loop)
    finally:
        conn_handle_future.cancel()
        request_timeout_future.cancel()
        shutdown_future.cancel()
        yield from conn_close_socks_server(socks_server_environ, conn, address)
        print('*** {!r}: CLOSED ***'.format(address))

@asyncio.coroutine
def accept_socks_server(socks_server_environ):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    socks_socket = socks_server_environ['socks_socket']
    
    conn, address = yield from loop.sock_accept(socks_socket)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    
    is_allowed = True
    
    for feature in features:
        accept_hook = feature.get('accept_hook')
        if accept_hook is not None:
            accept_hook_result = yield from accept_hook(socks_server_environ, {
                    'conn': conn,
                    'address': address,
                    })
            
            if accept_hook_result is not None:
                assert isinstance(accept_hook_result, bool)
                
                is_allowed = accept_hook_result
                
                if is_allowed:
                    # positive if at least one feature hook is positive
                    
                    break
    
    if not is_allowed:
        yield from conn_close_socks_server(socks_server_environ, conn, address)
        return
    
    conn_handle_future = asyncio.async(
            conn_handle_socks_server(socks_server_environ, conn, address),
            loop=loop,
            )
    
    return conn_handle_future

@asyncio.coroutine
def serve_socks_server(socks_server_environ):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    shutdown_event = socks_server_environ['shutdown_event']
    
    for feature in features:
        serve_init_hook = feature.get('serve_init_hook')
        if serve_init_hook is not None:
            yield from serve_init_hook(socks_server_environ, {'loop': loop})
    
    @asyncio.coroutine
    def shutdown_coro():
        yield from shutdown_event.wait()
        accept_future.cancel()
    
    conn_handle_future_list = []
    try:
        while True:
            shutdown_future, accept_future = \
                    asyncio.async(shutdown_coro(), loop=loop), \
                    asyncio.async(accept_socks_server(socks_server_environ), loop=loop)
            try:
                yield from asyncio.wait((accept_future, ), loop=loop)
                
                if not accept_future.cancelled():
                    conn_handle_future = accept_future.result()
                    # XXX: ``conn_handle_future`` may be ``None``
                    #           if we not want to accept (for some clients)
                    if conn_handle_future is not None:
                        conn_handle_future_list.append(conn_handle_future)
                
                conn_handle_future_list[:] = (
                        conn_handle_future
                        for conn_handle_future in conn_handle_future_list
                        if not conn_handle_future.done()
                        )
                
                if shutdown_event.is_set():
                    if conn_handle_future_list:
                        yield from asyncio.wait(conn_handle_future_list, loop=loop)
                        conn_handle_future_list[:] = ()
                    return 
            finally:
                shutdown_future.cancel()
                accept_future.cancel()
    finally:
        for conn_handle_future in conn_handle_future_list:
            conn_handle_future.cancel()
