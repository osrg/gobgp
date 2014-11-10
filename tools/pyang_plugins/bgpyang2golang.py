# Copyright (C) 2013,2014 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013,2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# this is a pyang plugin to generate ryu/lib/of_config/generated_classes.py
# usage example:
# PYTHONPATH=. ./bin/pyang --plugindir ~/git/ryu/tools/pyang_plugins -f ryu ~/git/ryu/tools/of-config1.1.1.yang > ~/git/ryu/lib/of_config/generated_classes.py


_COPYRIGHT_NOTICE = """
// Copyright (C) 2013,2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
"""


import sys
import StringIO
import pyang
from pyang import plugin

struct_map = {}

def pyang_plugin_init():
    plugin.register_plugin(GolangPlugin())


class GolangPlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        fmts['golang'] = self

    def emit(self, ctx, modules, fd):
        emit_golang(ctx, modules[0], fd)


def emit_golang(ctx, module, fd):
    ctx.golang_struct_def = []
    visit_children(ctx, module, fd, module.i_children)
    ctx.golang_struct_def.reverse()
    done = set()

    generate_header(ctx)
    for struct in ctx.golang_struct_def:
        struct_name = struct.arg
        if struct_name in done:
            continue
        emit_class_def(struct, struct_name)
        done.add(struct_name)

    # generate_header(ctx)


def emit_class_def(c, struct_name):

    o = StringIO.StringIO()
    struct_name_org = struct_name
    struct_name = convert_to_gostruct(struct_name)
    struct_map[struct_name_org] = struct_name
    print >> o, '//struct for container %s' % struct_name_org
    print >> o, 'type %s struct {' % struct_name
    for child in c.i_children:
        val_name_org = child.arg
        val_name = convert_to_golang(child.arg)

        if is_leaf(child):
            type_obj = child.search_one('type')
            #if type_obj.arg == 'leafref':
            #    print type_obj.search_one('path').arg
            type_name = type_obj.arg if type_obj is not None else None
        else:
            if is_list(child):
                assert val_name_org in struct_map
                type_name = '[]'+ struct_map[val_name_org]
                val_name = val_name + 'List'
            if is_container(child):
                type_name = struct_map[val_name_org]
                val_name = val_name

        print >> o, '  %s\t%s' % (val_name, translate_type(type_name))
    print >> o, '}'
    print o.getvalue()


def visit_children(ctx, module, fd, children, prefix=''):
    for c in children:
        t = c.search_one('type')
        type_name = t.arg if t is not None else None
        #print '%skeyword->%s, arg->%s, type->%s' % (prefix, c.keyword, c.arg, type_name)
        if is_list(c) or is_container(c):
            ctx.golang_struct_def.append(c)
        if hasattr(c, 'i_children'):
            visit_children(ctx, module, fd, c.i_children, prefix + '  ')


def is_leaf(s):
    return s.keyword in ['leaf', 'leaf-list']

def is_list(s):
    return s.keyword in ['list']

def is_container(s):
    return s.keyword in ['container']

def generate_header(ctx):
    print _COPYRIGHT_NOTICE
    print 'package config'
    print ''


_type_translation_map = {
    'decimal64' : 'float64',
    'inet:ip-address': '*net.IP',
    'inet:ipv4-address': '*net.IP',
    'inet:as-number' : 'uint32',
    'rr-cluster-id-type' : 'uint32',
}

def translate_type(key):
    if _type_translation_map.has_key(key):
        return _type_translation_map[key]
    else:
        return key


def convert_to_gostruct(type_string):
    return convert_to_golang(type_string) + 'Type'


# 'hoge-hoge' -> 'HogeHoge'
def convert_to_golang(type_string):
    a = type_string.split('-')
    a = map(lambda x: x.capitalize(), a)  # XXX locale sensitive
    return ''.join(a)

