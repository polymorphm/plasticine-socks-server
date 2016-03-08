# -*- mode: python; coding: utf-8 -*-
#
# Copyright (c) 2014, 2015 Andrej Antonov <polymorphm@gmail.com>
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

REQUEST_TIMEOUT = 15.0
READER_LIMIT = 1000000
READER_BUF = 100000

READ_IDLE_BUF = object()

def socks_server_preinit(socks_server_environ, features=None):
    socks_server_environ['shutdown_event'] = asyncio.Event()
    socks_server_environ['loop'] = None
    socks_server_environ['socks_sock_list'] = None
    
    if features is None:
        features = ()
    
    socks_server_environ['features'] = features
    
    for feature in features:
        preinit_hook = feature.get('preinit_hook')
        if preinit_hook is not None:
            preinit_hook(socks_server_environ, {})

def socks_server_create_socks_sock(socks_server_environ, unix=None, ip=None, port=None):
    assert unix is None or isinstance(unix, str)
    assert ip is None or isinstance(ip, str)
    assert port is None or isinstance(port, int)
    
    if unix is None and port is None:
        port = 8080
    
    if unix is None and ip is None:
        ip = '::1'
    
    features = socks_server_environ['features']
    
    for feature in features:
        create_socks_sock_hook = feature.get('create_socks_sock_hook')
        if create_socks_sock_hook is not None:
            socks_sock_list = create_socks_sock_hook(socks_server_environ, {
                    'unix': unix,
                    'ip': ip,
                    'port': port,
                    })
            
            if socks_sock_list is not None:
                assert isinstance(socks_sock_list, (tuple, list))
                
                socks_server_environ['socks_sock_list'] = socks_sock_list
                return
    
    if hasattr(socket, 'AF_UNIX') and unix is not None:
        unix_new_path = '{}.new-{}'.format(unix, os.getpid())
        socks_sock = socket.socket(socket.AF_UNIX)
        
        socks_sock.bind(unix_new_path)
        os.rename(unix_new_path, unix)
    else:
        assert isinstance(ip, str)
        assert isinstance(port, int)
        
        socks_sock = socket.socket(socket.AF_INET6)
        
        if hasattr(socket, 'SO_REUSEADDR'):
            try:
                socks_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                # SO_REUSEADDR is nice, but not required
                pass
        
        socks_sock.bind((ip, port))
    
    socks_server_environ['socks_sock_list'] = socks_sock,

def socks_server_before_fork(socks_server_environ):
    for feature in socks_server_environ['features']:
        before_fork_hook = feature.get('before_fork_hook')
        if before_fork_hook is not None:
            before_fork_hook(socks_server_environ, {})

def socks_server_after_fork(socks_server_environ):
    for feature in socks_server_environ['features']:
        after_fork_hook = feature.get('after_fork_hook')
        if after_fork_hook is not None:
            after_fork_hook(socks_server_environ, {})

@asyncio.coroutine
def socks_server_shutdown(socks_server_environ, loop):
    # XXX shutdown may be executed before of execution init (or init completed)
    
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
def socks_server_init(socks_server_environ, loop):
    features = socks_server_environ['features']
    socks_server_environ['loop'] = loop
    
    for feature in features:
        init_hook = feature.get('init_hook')
        if init_hook is not None:
            yield from init_hook(socks_server_environ, {'loop': loop})

@asyncio.coroutine
def socks_server_client_close(socks_server_environ, client_reader, client_writer):
    features = socks_server_environ['features']
    
    try:
        for feature in features:
            close_hook = feature.get('close_hook')
            if close_hook is not None:
                close_hook_result = yield from close_hook(socks_server_environ, {
                        'client_reader': client_reader,
                        'client_writer': client_writer,
                        })
    finally:
        client_writer.close()

@asyncio.coroutine
def socks_server_client_auth(socks_server_environ, client_reader, client_writer):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    
    for feature in features:
        auth_handle_hook = feature.get('auth_handle_hook')
        if auth_handle_hook is not None:
            auth_handle_hook_result = yield from auth_handle_hook(socks_server_environ, {
                    'client_reader': client_reader,
                    'client_writer': client_writer,
                    })
            
            if auth_handle_hook_result is not None:
                assert isinstance(auth_handle_hook_result, bool)
                
                return auth_handle_hook_result
    
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
    
    for i in range(auth_count):
        try:
            recv_data = yield from client_reader.readexactly(1)
        except (EOFError, OSError):
            return False
        
        recv_data = struct.unpack('!B', recv_data)
        
        if recv_data[0] == 0x00:
            use_no_auth = True
    
    if not use_no_auth:
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
    
    return True

@asyncio.coroutine
def socks_server_remote_connection(
        socks_server_environ, client_reader, client_writer,
        remote_addr_type, remote_addr, remote_port):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    
    for feature in features:
        remote_connection_hook = feature.get('remote_connection_hook')
        if remote_connection_hook is not None:
            remote_connection_hook_result = yield from remote_connection_hook(
                    socks_server_environ, {
                            'client_reader': client_reader,
                            'client_writer': client_writer,
                            'remote_addr_type': remote_addr_type,
                            'remote_addr': remote_addr,
                            'remote_port': remote_port,
                            })
            
            if remote_connection_hook_result is not None:
                if not remote_connection_hook_result:
                    # remote connection fail
                    
                    return
                
                remote_reader, remote_writer = remote_connection_hook_result
                
                assert remote_writer.get_extra_info('socket').getsockopt(
                        socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                break
    else:
        try:
            remote_reader, remote_writer = yield from asyncio.open_connection(
                    host=remote_addr, port=remote_port, limit=READER_LIMIT, loop=loop)
        except OSError:
            return
        
        remote_writer.get_extra_info('socket').setsockopt(
                socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    
    return remote_reader, remote_writer

@asyncio.coroutine
def socks_server_client_handle(socks_server_environ, client_reader, client_writer):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    shutdown_event = socks_server_environ['shutdown_event']
    
    @asyncio.coroutine
    def shutdown_coro():
        yield from shutdown_event.wait()
        client_handle_future.cancel()
    
    @asyncio.coroutine
    def request_timeout_coro():
        yield from asyncio.sleep(REQUEST_TIMEOUT, loop=loop)
        client_handle_future.cancel()
    
    @asyncio.coroutine
    def client_handle_coro():
        is_allowed = yield from socks_server_client_auth(
                socks_server_environ, client_reader, client_writer)
        
        assert isinstance(is_allowed, bool)
        
        if not is_allowed:
            return
        
        try:
            recv_data = yield from client_reader.readexactly(1)
        except (EOFError, OSError):
            return
        
        recv_data = struct.unpack('!B', recv_data)
        
        if recv_data[0] != 0x05:
            # invalid SOCKS version
            
            return
        
        try:
            recv_data = yield from client_reader.readexactly(1)
        except (EOFError, OSError):
            return
        
        cmd_code = recv_data[0]
        
        if cmd_code != 0x01:
            # command not supported or invalid
            
            return
        
        try:
            recv_data = yield from client_reader.readexactly(2)
        except (EOFError, OSError):
            return
        
        recv_data = struct.unpack('!BB', recv_data)
        
        remote_addr_type_code = recv_data[1]
        
        if remote_addr_type_code == 0x01:
            remote_addr_type = 'ipv4'
            try:
                remote_addr_bytes = yield from client_reader.readexactly(4)
            except (EOFError, OSError):
                return
            
            remote_addr = socket.inet_ntop(socket.AF_INET, remote_addr_bytes)
        elif remote_addr_type_code == 0x03:
            remote_addr_type = 'domain'
            
            try:
                recv_data = yield from client_reader.readexactly(1)
            except (EOFError, OSError):
                return
            
            remote_addr_len = struct.unpack('!B', recv_data)[0]
            
            try:
                remote_addr_bytes = yield from client_reader.readexactly(remote_addr_len)
            except (EOFError, OSError):
                return
            
            remote_addr = remote_addr_bytes.decode(errors='replace')
        elif remote_addr_type_code == 0x04:
            remote_addr_type = 'ipv6'
            try:
                remote_addr_bytes = yield from client_reader.readexactly(16)
            except (EOFError, OSError):
                return
            
            remote_addr = socket.inet_ntop(socket.AF_INET6, remote_addr_bytes)
        else:
            # invalid address type
            
            return
        
        try:
            recv_data = yield from client_reader.readexactly(2)
        except (EOFError, OSError):
            return
        
        remote_port = struct.unpack('!H', recv_data)[0]
        
        for feature in features:
            before_remote_connection_hook = feature.get('before_remote_connection_hook')
            if before_remote_connection_hook is not None:
                before_remote_connection_hook_result = yield from before_remote_connection_hook(
                        socks_server_environ, {
                                'client_reader': client_reader,
                                'client_writer': client_writer,
                                'remote_addr_type': remote_addr_type,
                                'remote_addr': remote_addr,
                                'remote_port': remote_port,
                                })
                
                if before_remote_connection_hook_result is not None:
                    assert isinstance(before_remote_connection_hook_result, bool)
                    
                    is_allowed = before_remote_connection_hook_result
                    
                    if is_allowed:
                        # positive if at least one feature hook is positive
                        
                        break
        
        if not is_allowed:
            client_writer.write(struct.pack(
                    '!BB',
                    0x05, # SOCKS version number (must be 0x05 for this version)
                    0x02, # connection not allowed by ruleset
                    ))
            return
        
        remote_connection_result = yield from socks_server_remote_connection(
                socks_server_environ, client_reader, client_writer,
                remote_addr_type, remote_addr, remote_port)
        
        if remote_connection_result is None:
            client_writer.write(struct.pack(
                    '!BB',
                    0x05, # SOCKS version number (must be 0x05 for this version)
                    0x04, # host unreachable
                    ))
            return
        
        remote_reader, remote_writer = remote_connection_result
        
        try:
            for feature in features:
                after_remote_connection_hook = feature.get('after_remote_connection_hook')
                if after_remote_connection_hook is not None:
                    after_remote_connection_hook_result = yield from after_remote_connection_hook(
                            socks_server_environ, {
                                    'client_reader': client_reader,
                                    'client_writer': client_writer,
                                    'remote_addr_type': remote_addr_type,
                                    'remote_addr': remote_addr,
                                    'remote_port': remote_port,
                                    'remote_reader': remote_reader,
                                    'remote_writer': remote_writer,
                                    })
                    
                    if after_remote_connection_hook_result is not None:
                        assert isinstance(after_remote_connection_hook_result, bool)
                        
                        is_allowed = after_remote_connection_hook_result
                        
                        if is_allowed:
                            # positive if at least one feature hook is positive
                            
                            break
            
            if not is_allowed:
                client_writer.write(struct.pack(
                    '!BB',
                    0x05, # SOCKS version number (must be 0x05 for this version)
                    0x02, # connection not allowed by ruleset
                    ))
                return
            
            client_writer.write(struct.pack(
                    '!BBBB',
                    0x05, # SOCKS version number (must be 0x05 for this version)
                    0x00, # request granted
                    0x00, # reserved, must be 0x00
                    0x04, # address type: IPv6
                    ))
            client_writer.write(bytes(18)) # pseudo addr-and-port
            
            request_timeout_future.cancel()
            
            def client_read_coro():
                while True:
                    try:
                        buf = yield from client_reader.read(READER_BUF)
                    except OSError:
                        buf = b''
                    
                    for feature in features:
                        client_read_hook = feature.get('client_read_hook')
                        if client_read_hook is not None:
                            client_read_hook_result = yield from client_read_hook(socks_server_environ, {
                                    'client_reader': client_reader,
                                    'client_writer': client_writer,
                                    'remote_reader': remote_reader,
                                    'remote_writer': remote_writer,
                                    'buf': buf,
                                    })
                            
                            if client_read_hook_result is not None:
                                assert isinstance(client_read_hook_result, bytes) \
                                        or client_read_hook_result is READ_IDLE_BUF
                                
                                buf = client_read_hook_result
                                
                                if buf is READ_IDLE_BUF:
                                    break
                    
                    if buf is READ_IDLE_BUF:
                        continue
                    
                    if not buf:
                        return
                    
                    remote_writer.write(buf)
                    
                    try:
                        yield from remote_writer.drain()
                    except OSError:
                        return
            
            def remote_read_coro():
                while True:
                    try:
                        buf = yield from remote_reader.read(READER_BUF)
                    except OSError:
                        buf = b''
                    
                    for feature in features:
                        remote_read_hook = feature.get('remote_read_hook')
                        if remote_read_hook is not None:
                            remote_read_hook_result = yield from remote_read_hook(socks_server_environ, {
                                    'client_reader': client_reader,
                                    'client_writer': client_writer,
                                    'remote_reader': remote_reader,
                                    'remote_writer': remote_writer,
                                    'buf': buf,
                                    })
                            
                            if remote_read_hook_result is not None:
                                assert isinstance(remote_read_hook_result, bytes) \
                                        or remote_read_hook_result is READ_IDLE_BUF
                                
                                buf = remote_read_hook_result
                                
                                if buf is READ_IDLE_BUF:
                                    break
                    
                    if buf is READ_IDLE_BUF:
                        continue
                    
                    if not buf:
                        return
                    
                    client_writer.write(buf)
                    
                    try:
                        yield from client_writer.drain()
                    except OSError:
                        return
            
            client_read_future, remote_read_future = \
                    asyncio.async(client_read_coro(), loop=loop), \
                    asyncio.async(remote_read_coro(), loop=loop)
            try:
                yield from asyncio.wait(
                        (client_read_future, remote_read_future),
                        return_when=asyncio.FIRST_COMPLETED,
                        loop=loop,
                        )
                
                if client_read_future.done() and not client_read_future.cancelled():
                    # if not cancelled -- re-raise error
                    client_read_future.result()
                if remote_read_future.done() and not remote_read_future.cancelled():
                    # if not cancelled -- re-raise error
                    remote_read_future.result()
            finally:
                client_read_future.cancel()
                remote_read_future.cancel()
        finally:
            remote_writer.close()
    
    shutdown_future, request_timeout_future, client_handle_future = \
            asyncio.async(shutdown_coro(), loop=loop), \
            asyncio.async(request_timeout_coro(), loop=loop), \
            asyncio.async(client_handle_coro(), loop=loop)
    try:
        yield from asyncio.wait((client_handle_future,), loop=loop)
        
        if not client_handle_future.cancelled():
            # if not cancelled -- re-raise error
            client_handle_future.result()
    finally:
        client_handle_future.cancel()
        request_timeout_future.cancel()
        shutdown_future.cancel()

@asyncio.coroutine
def socks_server_accept(socks_server_environ, client_reader, client_writer):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    is_allowed = True
    
    try:
        for feature in features:
            accept_hook = feature.get('accept_hook')
            if accept_hook is not None:
                accept_hook_result = yield from accept_hook(socks_server_environ, {
                        'client_reader': client_reader,
                        'client_writer': client_writer,
                        })
                
                if accept_hook_result is not None:
                    assert isinstance(accept_hook_result, bool)
                    
                    is_allowed = accept_hook_result
                    
                    if is_allowed:
                        # positive if at least one feature hook is positive
                        
                        break
        
        if not is_allowed:
            return
        
        yield from socks_server_client_handle(socks_server_environ, client_reader, client_writer)
    finally:
        yield from socks_server_client_close(socks_server_environ, client_reader, client_writer)

@asyncio.coroutine
def socks_server_serve(socks_server_environ):
    features = socks_server_environ['features']
    loop = socks_server_environ['loop']
    shutdown_event = socks_server_environ['shutdown_event']
    socks_sock_list = socks_server_environ['socks_sock_list']
    
    for feature in features:
        serve_init_hook = feature.get('serve_init_hook')
        if serve_init_hook is not None:
            yield from serve_init_hook(socks_server_environ, {})
    
    @asyncio.coroutine
    def shutdown_coro():
        yield from shutdown_event.wait()
        for server in server_list:
            server.close()
    
    def client_connected_cb(client_reader, client_writer):
        client_writer.get_extra_info('socket').setsockopt(
                socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        accept_future = asyncio.async(
                socks_server_accept(socks_server_environ, client_reader, client_writer),
                loop=loop,
                )
        
        client_handle_future_list.append(accept_future)
        client_handle_future_list[:] = (
                client_handle_future
                for client_handle_future in client_handle_future_list
                if not client_handle_future.done()
                )
    
    client_handle_future_list = []
    try:
        server_list = tuple(
                (yield from asyncio.start_server(
                        client_connected_cb, sock=socks_sock, limit=READER_LIMIT, loop=loop))
                for socks_sock in socks_sock_list
                )
        shutdown_future = asyncio.async(shutdown_coro(), loop=loop)
        try:
            for server in server_list:
                yield from asyncio.wait((server.wait_closed(),), loop=loop)
            
            if shutdown_event.is_set():
                if client_handle_future_list:
                    yield from asyncio.wait(client_handle_future_list, loop=loop)
                    
                    for client_handle_future in client_handle_future_list:
                        if not client_handle_future.cancelled():
                            # if not cancelled -- re-raise error
                            client_handle_future.result()
                    
                    client_handle_future_list[:] = ()
        finally:
            for server in server_list:
                server.close()
            shutdown_future.cancel()
    finally:
        for client_handle_future in client_handle_future_list:
            client_handle_future.cancel()
