# -*- mode: python; coding: utf-8 -*-
#
# this file is example of pluggable feature for socks_server

assert str is not bytes

import functools
import asyncio
from .. import socks_server

def read_config_hook(hook_environ, hook_args):
    assert len(hook_args) == 2
    config = hook_args['config']
    config_section = hook_args['config_section']
    
    print('reading config...')
    
    # returns nothing

def preinit_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 0
    
    print('preinit...')
    
    # returns nothing

def create_socks_sock_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 3
    unix = hook_args['unix']
    ip = hook_args['ip']
    port = hook_args['port']
    
    print('creating socks socket (unix is {!r}; ip is {!r}; port is {!r})...'.format(
            unix, ip, port))
    
    # may return list of socket-objects.
    # returns nothing to ignore this hook.

def before_fork_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 0
    
    print('preparing to fork...')
    from os import getpid
    hook_environ['before_fork_pid'] = getpid()
    
    # returns nothing

def after_fork_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 0
    
    from os import getpid
    hook_environ['after_fork_pid'] = getpid()
    if hook_environ['after_fork_pid'] != hook_environ['before_fork_pid']:
        print('forked')
    else:
        print('fork missed')
    
    # returns nothing

@asyncio.coroutine
def shutdown_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 1
    loop = hook_args['loop']
    
    print('shutdown...')
    if hook_environ['loop'] is not None:
        loop = hook_environ['loop']
    else:
        hook_environ['loop'] = loop
    assert loop is hook_environ['loop']
    
    # returns nothing

@asyncio.coroutine
def init_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 1
    loop = hook_args['loop']
    
    print('init...')
    hook_environ['loop'] = loop
    assert loop is not None
    
    # returns nothing

@asyncio.coroutine
def serve_init_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 0
    
    loop = hook_environ['loop']
    assert loop is not None
    
    print('starting serve...')
    
    # returns nothing

@asyncio.coroutine
def close_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 2
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    print('{!r}: client closed'.format(
            client_writer.get_extra_info('peername'),
            ))
    
    # returns nothing

@asyncio.coroutine
def accept_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 2
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    print('{!r}: client accepted'.format(
            client_writer.get_extra_info('peername'),
            ))
    
    # may return ``True`` or ``False`` -- for allow or disallow client accepting.
    # returns nothing to ignore this hook.

@asyncio.coroutine
def auth_handle_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 2
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    print('{!r}: auth...'.format(
            client_writer.get_extra_info('peername'),
            ))
    
    # this hook must return ``True`` or ``False`` --
    #       if auth was performed (with using ``client_reader`` and ``client_writer``).
    # returns nothing to ignore this hook.

@asyncio.coroutine
def before_remote_connection_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 5
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    remote_addr_type = hook_args['remote_addr_type']
    remote_addr = hook_args['remote_addr']
    remote_port = hook_args['remote_port']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    print('{!r}: required connection to: {!r}/{!r}/{!r}'.format(
            client_writer.get_extra_info('peername'),
            remote_addr_type,
            remote_addr,
            remote_port,
            ))
    
    # may return ``True`` or ``False`` -- for allow or disallow connection.
    # returns nothing to ignore this hook.

@asyncio.coroutine
def remote_connection_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 5
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    remote_addr_type = hook_args['remote_addr_type']
    remote_addr = hook_args['remote_addr']
    remote_port = hook_args['remote_port']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    print('{!r}: opening connection to: {!r}/{!r}/{!r}...'.format(
            client_writer.get_extra_info('peername'),
            remote_addr_type,
            remote_addr,
            remote_port,
            ))
    
    # may return ``tuple(remote_reader, remote_writer)`` or ``False``.
    # returns nothing to ignore this hook.

@asyncio.coroutine
def after_remote_connection_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 7
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    remote_addr_type = hook_args['remote_addr_type']
    remote_addr = hook_args['remote_addr']
    remote_port = hook_args['remote_port']
    remote_reader = hook_args['remote_reader']
    remote_writer = hook_args['remote_writer']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    print('{!r}: connected to: {!r}'.format(
            client_writer.get_extra_info('peername'),
            remote_writer.get_extra_info('peername'),
            ))
    
    # may return ``True`` or ``False`` -- for allow or disallow connection.
    # returns nothing to ignore this hook.

@asyncio.coroutine
def client_read_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 5
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    remote_reader = hook_args['remote_reader']
    remote_writer = hook_args['remote_writer']
    buf = hook_args['buf']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    show_limit = 20
    if len(buf) > show_limit:
        show_buf = buf[:show_limit] + b'...'
    else:
        show_buf = buf
    
    print('{!r}: readed data ({!r} bytes) from client: {!r}'.format(
            client_writer.get_extra_info('peername'),
            len(buf),
            show_buf,
            ))
    
    # may return modified ``buf`` or may return ``socks_server.READ_IDLE_BUF``.
    # returns nothing to ignore this hook.

@asyncio.coroutine
def remote_read_hook(hook_environ, socks_server_environ, hook_args):
    assert len(hook_args) == 5
    client_reader = hook_args['client_reader']
    client_writer = hook_args['client_writer']
    remote_reader = hook_args['remote_reader']
    remote_writer = hook_args['remote_writer']
    buf = hook_args['buf']
    
    loop = hook_environ['loop']
    assert loop is not None
    
    show_limit = 20
    if len(buf) > show_limit:
        show_buf = buf[:show_limit] + b'...'
    else:
        show_buf = buf
    
    print('{!r}: readed data ({!r} bytes) from remote: {!r}'.format(
            client_writer.get_extra_info('peername'),
            len(buf),
            show_buf,
            ))
    
    # may return modified ``buf`` or may return ``socks_server.READ_IDLE_BUF``.
    # returns nothing to ignore this hook.

def socks_server_create_feature():
    hook_environ = {
            'loop': None,
            }
    
    return {
            'read_config_hook': functools.partial(read_config_hook, hook_environ),
            'preinit_hook': functools.partial(preinit_hook, hook_environ),
            'create_socks_sock_hook': functools.partial(create_socks_sock_hook, hook_environ),
            'before_fork_hook': functools.partial(before_fork_hook, hook_environ),
            'after_fork_hook': functools.partial(after_fork_hook, hook_environ),
            'shutdown_hook': functools.partial(shutdown_hook, hook_environ),
            'init_hook': functools.partial(init_hook, hook_environ),
            'serve_init_hook': functools.partial(serve_init_hook, hook_environ),
            'close_hook': functools.partial(close_hook, hook_environ),
            'accept_hook': functools.partial(accept_hook, hook_environ),
            'auth_handle_hook': functools.partial(auth_handle_hook, hook_environ),
            'before_remote_connection_hook': functools.partial(before_remote_connection_hook, hook_environ),
            'remote_connection_hook': functools.partial(remote_connection_hook, hook_environ),
            'after_remote_connection_hook': functools.partial(after_remote_connection_hook, hook_environ),
            'client_read_hook': functools.partial(client_read_hook, hook_environ),
            'remote_read_hook': functools.partial(remote_read_hook, hook_environ),
            }
