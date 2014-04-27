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

import os, os.path
import configparser

try:
    import fcntl
except ImportError:
    fcntl = None

def config_import(config_path):
    config = configparser.ConfigParser()
    
    with open(config_path, encoding='utf-8', errors='replace') as config_fd:
        if fcntl is not None:
            fcntl.flock(config_fd, fcntl.LOCK_SH)
        
        config.read_file(config_fd)
        import_config_str = config.get('plasticine-socks-server', 'import', fallback=None)
        
        if import_config_str is None:
            return config
        
        base_config_path_list = tuple(
                os.path.join(os.path.dirname(config_path), x)
                for x in import_config_str.split()
                )
        
        # do ``config_import(...)`` recursively
        base_config_list = tuple(
                config_import(x)
                for x in base_config_path_list
                )
        
        meta_config = configparser.ConfigParser()
        
        for base_config in base_config_list:
            for base_config_sec in base_config:
                if base_config_sec not in meta_config:
                    meta_config[base_config_sec] = {}
                meta_config[base_config_sec].update(base_config[base_config_sec])
        
        for config_sec in config:
            if config_sec not in meta_config:
                meta_config[config_sec] = {}
            meta_config[config_sec].update(config[config_sec])
        
        return meta_config
