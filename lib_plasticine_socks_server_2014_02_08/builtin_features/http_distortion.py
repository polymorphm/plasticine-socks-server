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
import weakref

@asyncio.coroutine
def init_hook(hook_environ, socks_server_environ, hook_args):
    loop = hook_args['loop']
    hook_environ['loop'] = loop
    assert loop is not None

@asyncio.coroutine
def client_read_hook(hook_environ, socks_server_environ, hook_args):
    client_writer = hook_args['client_writer']
    remote_writer = hook_args['remote_writer']
    buf = hook_args['buf']
    
    loop = hook_environ['loop']
    client_map = hook_environ['client_map']
    assert loop is not None
    
    peername = remote_writer.get_extra_info('peername')
    if peername[1] != 80:
        return
    
    try:
        client_item = client_map[client_writer]
    except KeyError:
        client_map[client_writer] = client_item = {
                'acc_buf': b'',
                }
    
    client_item['acc_buf'] += buf
    
    modified_acc_buf = client_item['acc_buf'].\
            replace(b'\r\nHost', b'\r\nHosT')
    if modified_acc_buf != client_item['acc_buf']:
        buf = modified_acc_buf[-len(buf):]
    
    if len(client_item['acc_buf']) >= 20:
        client_item['acc_buf'] = client_item['acc_buf'][-20:]
    
    return buf

def socks_server_create_feature():
    hook_environ = {
            'loop': None,
            'client_map': weakref.WeakKeyDictionary(),
            }
    
    return {
            'init_hook': functools.partial(init_hook, hook_environ),
            'client_read_hook': functools.partial(client_read_hook, hook_environ),
            }
