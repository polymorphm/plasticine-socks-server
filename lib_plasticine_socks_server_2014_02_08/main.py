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

import argparse
import configparser
import os
import asyncio
import signal
from . import socks_server

def get_feature_by_shortcut(feature):
    if not isinstance(feature, str):
        return feature
    
    # TODO ... if feature == '...': return '......'
    
    return feature

def main():
    parser = argparse.ArgumentParser(
            description='SOCKS (SOCKS Protocol Version 5) server with '
                    'support non-regular use cases via plugins',
            )
    
    parser.add_argument(
            '--not-use-fork',
            action='store_true',
            help='not do use fork operation',
            )
    parser.add_argument(
            '--not-show-pid',
            action='store_true',
            help='not show pid when doing fork',
            )
    parser.add_argument(
            'config',
            metavar='CONFIG-PATH',
            help='path to config file',
            )
    
    args = parser.parse_args()
    
    config = configparser.ConfigParser()
    config.read_file(open(args.config, mode='r', encoding='utf-8', errors='replace'))
    
    features_str = config.get('plasticine-socks-server', 'features', fallback=None)
    unix = config.get('plasticine-socks-server', 'unix', fallback=None)
    ip = config.get('plasticine-socks-server', 'ip', fallback=None)
    port = config.getint('plasticine-socks-server', 'port', fallback=None)
    
    if features_str:
        feature_names = tuple(map(
                get_feature_by_shortcut,
                filter(
                        None,
                        (w.strip() for w in features_str.split(',')),
                        ),
                ))
        features = tuple(
                importlib(feature_name).create_socks_server_feature()
                for feature_name in feature_names
                )
        
        for feature in features:
            read_config_hook = feature.get('read_config_hook')
            if read_config_hook:
                read_config_hook({'config': config})
    else:
        features = None
    
    socks_server_environ = {}
    
    socks_server.preinit_socks_server(
            socks_server_environ,
            features=features,
            )
    
    socks_server.create_socks_sock_socks_server(
            socks_server_environ,
            unix=unix,
            ip=ip,
            port=port,
            )
    
    socks_server.before_fork_socks_server(socks_server_environ)
    
    if not args.not_use_fork:
        pid = os.fork()
        if pid:
            if not args.not_show_pid:
                print(pid)
            os._exit(0)
    
    socks_server.after_fork_socks_server(socks_server_environ)
    
    loop = asyncio.get_event_loop()
    
    def shutdown_handler():
        # XXX shutdown may be executed before of execution init (or init completed)
        asyncio.async(
                socks_server.shutdown_socks_server(socks_server_environ, loop),
                loop=loop,
                )
    loop.add_signal_handler(signal.SIGINT, shutdown_handler)
    loop.add_signal_handler(signal.SIGTERM, shutdown_handler)
    
    init_future = asyncio.async(
            socks_server.init_socks_server(socks_server_environ, loop),
            loop=loop,
            )
    
    loop.run_until_complete(init_future)
    
    serve_future = asyncio.async(
            socks_server.serve_socks_server(socks_server_environ),
            loop=loop,
            )
    
    loop.run_until_complete(serve_future)
