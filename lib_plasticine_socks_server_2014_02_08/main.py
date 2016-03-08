# -*- mode: python; coding: utf-8 -*-
#
# Copyright (c) 2014, 2015, 2016 Andrej Antonov <polymorphm@gmail.com>
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

import argparse
import configparser
import importlib
import os
import asyncio
import signal
from . import config_import
from . import socks_server

try:
    from  systemd import daemon
except ImportError:
    daemon = None

BUILTIN_FEATURE_NAMESPACE = '{}.builtin_features'.format(
        __name__.rsplit('.', maxsplit=1)[0]
        )
BUILTIN_FEATURE_NAME_LIST = (
        'addrinfo',
        'http_distortion',
        'multi_channel_perm',
        )

def get_feature_by_shortcut(feature_name):
    assert isinstance(feature_name, str)
    
    if feature_name in BUILTIN_FEATURE_NAME_LIST:
        return '{}.{}'.format(BUILTIN_FEATURE_NAMESPACE, feature_name)
    
    return feature_name

def import_features(features_str, config, config_path):
    assert isinstance(features_str, str)
    
    features = []
    
    for feature_shortcut_name in features_str.split():
        feature_name = get_feature_by_shortcut(feature_shortcut_name)
        feature_module = importlib.import_module(feature_name)
        if not hasattr(feature_module, 'socks_server_create_feature'):
            raise ImportError('module {!r} has not feature factory'.format(
                    feature_module))
        
        feature = feature_module.socks_server_create_feature()
        
        read_config_hook = feature.get('read_config_hook')
        if read_config_hook:
            read_config_hook({
                    'config': config,
                    'config_path': config_path,
                    'config_section': feature_shortcut_name,
                    })
        
        features.append(feature)
    
    return tuple(features)

def write_pid(pid_file, pid):
    with open(pid_file, mode='w', encoding='utf-8', newline='\n') as pid_fd:
        pid_fd.write('{}\n'.format(pid))

def main():
    parser = argparse.ArgumentParser(
            description='SOCKS (SOCKS Protocol Version 5) server with '
                    'support non-regular use cases via pluggable features',
            )
    
    parser.add_argument(
            '--use-fork',
            action='store_true',
            help='use fork operation (after sockets creation)',
            )
    parser.add_argument(
            '--pid-file',
            metavar='PID-FILE-PATH',
            help='path to pid file',
            )
    parser.add_argument(
            'config',
            metavar='CONFIG-PATH',
            help='path to config file',
            )
    
    args = parser.parse_args()
    
    config = config_import.config_import(args.config)
    
    features_str = config.get('plasticine-socks-server', 'features', fallback=None)
    unix = config.get('plasticine-socks-server', 'unix', fallback=None)
    ip = config.get('plasticine-socks-server', 'ip', fallback=None)
    port = config.getint('plasticine-socks-server', 'port', fallback=None)
    
    if features_str:
        features = import_features(features_str, config, args.config)
    else:
        features = None
    
    socks_server_environ = {}
    
    socks_server.socks_server_preinit(
            socks_server_environ,
            features=features,
            )
    
    socks_server.socks_server_create_socks_sock(
            socks_server_environ,
            unix=unix,
            ip=ip,
            port=port,
            )
    
    socks_server.socks_server_before_fork(socks_server_environ)
    
    if args.use_fork:
        pid = os.fork()
        if pid:
            # XXX if used fork: than *parent* must to write pid of child
            if args.pid_file is not None:
                write_pid(args.pid_file, pid)
            
            os._exit(0)
    elif args.pid_file is not None:
        write_pid(args.pid_file, os.getpid())
    
    if daemon is not None:
        daemon.notify(
                'READY=1\nMAINPID={}'.format(os.getpid()),
                unset_environment=True,
                )
    
    socks_server.socks_server_after_fork(socks_server_environ)
    
    loop = asyncio.get_event_loop()
    
    def shutdown_handler():
        # XXX shutdown may be executed before of execution init (or init completed)
        asyncio.async(
                socks_server.socks_server_shutdown(socks_server_environ, loop),
                loop=loop,
                )
    try:
        loop.add_signal_handler(signal.SIGINT, shutdown_handler)
    except NotImplementedError:
        pass
    try:
        loop.add_signal_handler(signal.SIGTERM, shutdown_handler)
    except NotImplementedError:
        pass
    
    init_future = asyncio.async(
            socks_server.socks_server_init(socks_server_environ, loop),
            loop=loop,
            )
    
    loop.run_until_complete(init_future)
    
    serve_future = asyncio.async(
            socks_server.socks_server_serve(socks_server_environ),
            loop=loop,
            )
    
    loop.run_until_complete(serve_future)
    
    try:
        loop.remove_signal_handler(signal.SIGINT)
    except NotImplementedError:
        pass
    try:
        loop.remove_signal_handler(signal.SIGTERM)
    except NotImplementedError:
        pass
