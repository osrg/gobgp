# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

# this is a pyang plugin to generate $GOBGP_PATH/config/bgp_configs.go
# usage example:
# GOBGP_PATH=$GOPATH/src/github.com/osrg/gobgp
# cd $PYANG_INSTALL_DIR
# source ./env.sh
# PYTHONPATH=. ./bin/pyang --plugindir $GOBGP_PATH/tools/pyang_plugins \
#  -p $GOBGP_PATH/tools/yang/ -f golang \
#  $GOBGP_PATH/tools/yang/bgp.yang > out.go
# gofmt out.go > $GOBGP_PATH/config/bgp_configs.go
#
# NOTICE: copy related yang files into $PYANG_INSTALL_DIR/modules/ in advance.

import StringIO
from pyang import plugin

_COPYRIGHT_NOTICE = """
// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

emitted_type_names = []


def pyang_plugin_init():
    plugin.register_plugin(GolangPlugin())


class GolangPlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        fmts['golang'] = self

    def emit(self, ctx, modules, fd):
        emit_golang(ctx, modules[0], fd)


def emit_golang(ctx, module, fd):

    ctx.golang_identity_map = {}
    ctx.golang_typedef_map = {}
    ctx.golang_struct_def = []
    ctx.golang_struct_names = {}

    # visit typedef
    visit_typedef(ctx, module)
    visit_typedef(ctx, ctx.get_module('bgp-policy'))
    #visit_typedef(ctx, ctx.get_module('routing-policy'))
    visit_typedef(ctx, ctx.get_module('bgp-multiprotocol'))
    visit_typedef(ctx, ctx.get_module('bgp-operational'))
    # visit identity
    visit_identity(ctx, ctx.get_module('bgp-policy'))
    #visit_identity(ctx, ctx.get_module('routing-policy'))
    visit_identity(ctx, ctx.get_module('bgp-multiprotocol'))
    visit_identity(ctx, ctx.get_module('bgp-operational'))

    visit_children(ctx, module, module.i_children)
    ctx.golang_struct_def.reverse()
    done = set()

    # emit
    generate_header(ctx)

    emit_typedef(ctx, module)
    emit_typedef(ctx, ctx.get_module('bgp-policy'))
    # emit_typedef(ctx, ctx.get_module('routing-policy'))
    emit_typedef(ctx, ctx.get_module('bgp-multiprotocol'))
    emit_typedef(ctx, ctx.get_module('bgp-operational'))


    for struct in ctx.golang_struct_def:
        struct_name = struct.arg
        if struct_name in done:
            continue
        emit_class_def(ctx, struct, struct_name)
        done.add(struct_name)


def emit_class_def(ctx, c, struct_name):

    o = StringIO.StringIO()
    struct_name_org = struct_name
    struct_name = convert_to_golang(struct_name)

    print >> o, '//struct for container %s' % struct_name_org
    print >> o, 'type %s struct {' % struct_name
    for child in c.i_children:

        val_name = child.arg
        val_name_go = convert_to_golang(child.arg)
        module_name = child.i_orig_module.i_prefix

        print >> o, '  // original -> %s:%s' % (module_name, val_name)

        # case leaf
        if is_leaf(child):
            type_obj = child.search_one('type')
            type_name = type_obj.arg

            # case identityref
            if type_name == 'identityref':
                emit_type_name = 'string'

            # case leafref
            elif type_name == 'leafref':
                t = type_obj.i_type_spec.i_target_node.search_one('type')
                emit_type_name = t.arg

            # case translation required
            elif is_translation_required(type_obj):
                print >> o, '  //%s\'s original type is %s'\
                            % (val_name, type_obj.arg)
                emit_type_name = translate_type(type_name)

            # case other primitives
            elif is_builtin_type(type_obj):
                emit_type_name = type_name

            # default
            else:
                base_module = type_obj.i_orig_module.i_prefix
                t = lookup_typedef(ctx, base_module, type_name)
                emit_type_name = t.golang_name

        # case leaflist
        if is_leaflist(child):
            type_obj = child.search_one('type')
            type_name = type_obj.arg

            # case leafref
            if type_name == 'leafref':
                t = type_obj.i_type_spec.i_target_node.search_one('type')
                emit_type_name = '[]'+t.arg

            # case translation required
            elif is_translation_required(type_obj):
                print >> o, '  //original type is list of %s' % (type_obj.arg)
                emit_type_name = '[]'+translate_type(type_name)

            # case other primitives
            elif is_builtin_type(type_obj):
                emit_type_name = '[]'+type_name

            # default
            else:
                base_module = type_obj.i_orig_module.i_prefix
                t = lookup_typedef(ctx, base_module, type_name)
                emit_type_name = '[]'+t.golang_name

        # case container
        elif is_container(child):
            t = ctx.golang_struct_names[val_name]
            emit_type_name = t.golang_name

        # case list
        elif is_list(child):
            t = ctx.golang_struct_names[val_name]
            val_name_go = val_name_go + 'List'
            emit_type_name = '[]' + t.golang_name

        if is_container(child):
            print >> o, '  %s' % emit_type_name
        else:
            print >> o, '  %s\t%s' % (val_name_go, emit_type_name)

    print >> o, '}'
    print o.getvalue()


def visit_children(ctx, module, children, prefix=''):
    for c in children:
        t = c.search_one('type')
        type_name = t.arg if t is not None else None
        if is_list(c) or is_container(c):
            c.golang_name = convert_to_golang(c.arg)
            ctx.golang_struct_def.append(c)
            ctx.golang_struct_names[c.arg] = c
        if hasattr(c, 'i_children'):
            visit_children(ctx, module, c.i_children, prefix + '  ')


def visit_typedef(ctx, module):
    prefix = module.i_prefix
    child_map = {}
    for stmts in module.substmts:
        if stmts.keyword == 'typedef':
            name = stmts.arg
            stmts.golang_name = convert_to_golang(name)
            if stmts.golang_name == 'PeerType':
                stmts.golang_name = 'PeerTypeDef'
            child_map[name] = stmts
    ctx.golang_typedef_map[prefix] = child_map


def visit_identity(ctx, module):
    prefix = module.i_prefix
    child_map = {}
    for stmts in module.substmts:
        if stmts.keyword == 'identity':
            name = stmts.arg
            stmts.golang_name = convert_to_golang(name)
            child_map[name] = stmts
    ctx.golang_identity_map[prefix] = child_map


def lookup_identity(ctx, default_prefix, identity_name):
    result = lookup(ctx.golang_identity_map, default_prefix, identity_name)
    return result


def lookup_typedef(ctx, default_prefix, type_name):
    result = lookup(ctx.golang_typedef_map, default_prefix, type_name)
    return result


def lookup(basemap, default_prefix, key):
    if ':' in key:
        pref, name = key.split(':')
    else:
        pref = default_prefix
        name = key

    if pref in basemap:
        return basemap[pref].get(name, None)
    else:
        return key


def emit_typedef(ctx, module):
    prefix = module.i_prefix
    t_map = ctx.golang_typedef_map[prefix]
    for name, stmt in t_map.items():
        type_name_org = name
        type_name = stmt.golang_name
        if type_name in emitted_type_names:
            continue

        emitted_type_names.append(type_name)

        t = stmt.search_one('type')
        o = StringIO.StringIO()

        if t.arg == 'enumeration':
            print >> o, '// typedef for typedef %s:%s'\
                        % (prefix, type_name_org)
            print >> o, 'type %s int' % (type_name)

            const_prefix = convert_const_prefix(type_name_org)
            print >> o, 'const ('

            already_added_iota = False
            for sub in t.substmts:
                if sub.search_one('value'):
                    enum_value = " = "+sub.search_one('value').arg
                else:
                    if already_added_iota:
                        enum_value = ""
                    else:
                        enum_value = " = iota"
                        already_added_iota = True
                enum_name = convert_const_prefix(sub.arg)
                print >> o, ' %s_%s%s' % (const_prefix, enum_name, enum_value)
            print >> o, ')'
        elif t.arg == 'union':
            print >> o, '// typedef for typedef %s:%s'\
                        % (prefix, type_name_org)
            print >> o, 'type %s string' % (type_name)
        else:
            print >> o, '// typedef for typedef %s:%s'\
                        % (prefix, type_name_org)
            print >> o, 'type %s %s' % (type_name, t.arg)

        print o.getvalue()


def emit_identity(ctx, module):

    prefix = module.i_prefix
    i_map = ctx.golang_identity_map[prefix]
    for name, stmt in i_map.items():
        type_name_org = name
        type_name = stmt.golang_name
        base = stmt.search_one('base')
        o = StringIO.StringIO()

        print >> o, '// typedef for identity %s:%s' % (prefix, type_name_org)
        print >> o, 'type %s struct {' % (type_name)
        if base is not None:
            base_obj = lookup_identity(ctx, prefix, base.arg)
            print >> o, ' // base_type -> %s' % (base.arg)
            print >> o, ' %s' % (base_obj.golang_name)

        print >> o, '}'
        print o.getvalue()


def is_reference(s):
    return s.arg in ['leafref', 'identityref']


def is_leaf(s):
    return s.keyword in ['leaf']


def is_leaflist(s):
    return s.keyword in ['leaf-list']


def is_list(s):
    return s.keyword in ['list']


def is_container(s):
    return s.keyword in ['container']


def is_builtin_type(t):
    return t.arg in _type_builtin


def is_translation_required(t):
    return t.arg in _type_translation_map.keys()


_type_translation_map = {
    'union': 'string',
    'enumeration': 'string',
    'decimal64': 'float64',
    'boolean': 'bool',
    'empty': 'bool',
    'inet:ip-address': 'net.IP',
    'inet:ipv4-address': 'net.IP',
    'inet:as-number': 'uint32',
    'rr-cluster-id-type': 'uint32',
}


_type_builtin = ["union",
                 "int8",
                 "int16",
                 "int32",
                 "int64",
                 "string",
                 "uint8",
                 "uint16",
                 "uint32",
                 "uint64",
                 ]


def generate_header(ctx):
    print _COPYRIGHT_NOTICE
    print 'package config'
    print ''
    print 'import "net"'
    print ''


def translate_type(key):
    if key in _type_translation_map.keys():
        return _type_translation_map[key]
    else:
        return key


# 'hoge-hoge' -> 'HogeHoge'
def convert_to_golang(type_string):
    a = type_string.split('-')
    a = map(lambda x: x.capitalize(), a)  # XXX locale sensitive
    return ''.join(a)


# 'hoge-hoge' -> 'HOGE_HOGE'
def convert_const_prefix(type_string):
    a = type_string.split('-')
    a = map(lambda x: x.upper(), a)  # XXX locale sensitive
    return '_'.join(a)


def chop_suf(s, suf):
    if not s.endswith(suf):
        return s
    return s[:-len(suf)]
