# Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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


import optparse
import StringIO
import sys
from pyang import plugin

_COPYRIGHT_NOTICE = """
// Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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

emitted_type_names = {}


def pyang_plugin_init():
    plugin.register_plugin(GolangPlugin())


class GolangPlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        fmts['golang'] = self



    def add_opts(self, optparser):
        optlist = [
            optparse.make_option("--augment",
                                 dest="augment", action="append",
                                 help="Yang file which has augment statements"),
            ]
        g = optparser.add_option_group("GolangPlugin specific options")
        g.add_options(optlist)



    def emit(self, ctx, modules, fd):

        ctx.golang_identity_map = {}
        ctx.golang_typedef_map = {}
        ctx.golang_struct_def = []
        ctx.golang_struct_names = {}

        ctx.prefix_rel = {}
        ctx.module_deps = []

        check_module_deps(ctx, modules[0])

        # load augment module
        if ctx.opts.augment:
            aug_mod_path = ctx.opts.augment
            for p in aug_mod_path:
                with open(p) as fd:
                    try:
                        text = fd.read()
                    except IOError as ex:
                        sys.stderr.write("error %s: %s\n" % (aug_mod_path, str(ex)))
                        sys.exit(1)
                    aug_mod = ctx.add_module(p, text)
                    check_module_deps(ctx, aug_mod)

        # visit yang statements
        visit_modules(ctx)
        # emit bgp_configs
        emit_go(ctx)


def visit_modules(ctx):

    # visit typedef and identity
    for module in ctx.module_deps:
        visit_typedef(ctx, module)
        visit_identity(ctx, module)

    # visit container
    for module in ctx.module_deps:
        visit_children(ctx, module, module.i_children)


def emit_go(ctx):

    ctx.golang_struct_def.reverse()
    done = set()

    # emit
    generate_header(ctx)

    for mod in ctx.module_deps:
        if mod not in _module_excluded:
            emit_typedef(ctx, mod)

    for struct in ctx.golang_struct_def:
        struct_name = struct.uniq_name
        if struct_name in done:
            continue
        emit_class_def(ctx, struct, struct_name, struct.module_prefix)
        done.add(struct_name)


def check_module_deps(ctx, module):

    own_prefix = module.i_prefix
    for k, v in module.i_prefixes.items():
        mod = ctx.get_module(v[0])
        if mod.i_prefix != own_prefix:
            check_module_deps(ctx, mod)

        ctx.prefix_rel[mod.i_prefix] = k
        if mod not in ctx.module_deps \
                and mod.i_modulename not in _module_excluded:
            ctx.module_deps.append(mod)


def dig_leafref(type_obj):
    reftype = type_obj.i_type_spec.i_target_node.search_one('type')
    if is_leafref(reftype):
        return dig_leafref(reftype)
    else:
        return reftype


def emit_class_def(ctx, yang_statement, struct_name, prefix):

    o = StringIO.StringIO()
    print >> o, '//struct for container %s:%s' % (prefix, yang_statement.arg)
    print >> o, 'type %s struct {' % convert_to_golang(struct_name)
    for child in yang_statement.i_children:

        if child.path in _path_exclude:
            continue

        container_or_list_name = child.uniq_name
        val_name_go = convert_to_golang(child.arg)
        child_prefix = get_orig_prefix(child.i_orig_module)
        print >> o, '  // original -> %s:%s' % \
                    (child_prefix, container_or_list_name)

        # case leaf
        if is_leaf(child):
            type_obj = child.search_one('type')
            type_name = type_obj.arg


            # case identityref
            if type_name == 'identityref':
                emit_type_name = 'string'

            # case leafref
            elif type_name == 'leafref':
                t = dig_leafref(type_obj)
                if is_translation_required(t):
                    print >> o, '  //%s:%s\'s original type is %s' \
                                % (child_prefix, container_or_list_name, t.arg)
                    emit_type_name = translate_type(t.arg)
                else:
                    emit_type_name = t.arg


            # case translation required
            elif is_translation_required(type_obj):
                print >> o, '  //%s:%s\'s original type is %s'\
                            % (child_prefix, container_or_list_name, type_name)
                emit_type_name = translate_type(type_name)

            # case other primitives
            elif is_builtin_type(type_obj):
                emit_type_name = type_name

            # default
            else:
                base_module = type_obj.i_orig_module.i_prefix
                t = lookup_typedef(ctx, base_module, type_name)
                # print(t)
                emit_type_name = t.golang_name

        # case 'case'
        if is_case(child):
            continue

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
        elif is_container(child) or is_choice(child):
            key = child_prefix+':'+container_or_list_name
            t = ctx.golang_struct_names[key]
            emit_type_name = t.golang_name

        # case list
        elif is_list(child):
            key = child_prefix+':'+container_or_list_name
            t = ctx.golang_struct_names[key]
            val_name_go = val_name_go + 'List'
            emit_type_name = '[]' + t.golang_name

        if is_container(child):
            print >> o, '  %s\t%s' % (emit_type_name, emit_type_name)
        else:
            print >> o, '  %s\t%s' % (val_name_go, emit_type_name)

    print >> o, '}'
    print o.getvalue()


def get_orig_prefix(module):
    orig = module.i_orig_module
    if orig:
        get_orig_prefix(orig)
    else:
        return module.i_prefix


def get_path(c):
    path = ''
    if c.parent is not None:
        p = ''
        if hasattr(c, 'i_module'):
            mod = c.i_module
            prefix = mod.search_one('prefix')

        p = prefix.arg + ":" if prefix else ''
        path = get_path(c.parent) + "/" + p + c.arg
    return path


def visit_children(ctx, module, children):
    for c in children:
        prefix = ''
        if is_case(c):
            prefix = get_orig_prefix(c.parent.i_orig_module)
            c.i_orig_module = c.parent.i_orig_module
        else:
            prefix = get_orig_prefix(c.i_orig_module)

        c.uniq_name = c.arg
        if c.arg == 'config':
            c.uniq_name = c.parent.uniq_name + '-config'

        if c.arg == 'state':

            c.uniq_name = c.parent.uniq_name + '-state'

        if c.arg == 'graceful-restart' and prefix == 'bgp-mp':
             c.uniq_name = 'mp-graceful-restart'

        t = c.search_one('type')

        if is_list(c) or is_container(c) or is_choice(c):
            c.golang_name = convert_to_golang(c.uniq_name)

            if is_choice(c):
                picks = pickup_choice(c)
                c.i_children = picks

            if ctx.golang_struct_names.get(prefix+':'+c.uniq_name):
                ext_c = ctx.golang_struct_names.get(prefix+':'+c.uniq_name)
                ext_c_child_count = len(getattr(ext_c, "i_children"))
                current_c_child_count = len(getattr(c, "i_children"))
                if ext_c_child_count < current_c_child_count:
                    c.module_prefix = prefix
                    ctx.golang_struct_names[prefix+':'+c.uniq_name] = c
                    idx = ctx.golang_struct_def.index(ext_c)
                    ctx.golang_struct_def[idx] = c
            else:
                c.module_prefix = prefix
                ctx.golang_struct_names[prefix+':'+c.uniq_name] = c
                ctx.golang_struct_def.append(c)

        c.path = get_path(c)
        # print(c.path)
        if hasattr(c, 'i_children'):
            visit_children(ctx, module, c.i_children)


def pickup_choice(c):
    element = []
    for child in c.i_children:
        if is_case(child):
            element = element + child.i_children

    return element


def get_type_spec(stmt):
    for s in stmt.substmts:
        if hasattr(s, 'i_type_spec'):
            type_sp = s.i_type_spec
            return type_sp.name

    return None


def visit_typedef(ctx, module):
    prefix = module.i_prefix
    child_map = {}
    for stmts in module.substmts:
        if stmts.keyword == 'typedef':
            stmts.path = get_path(stmts)
            # print(stmts.path)
            name = stmts.arg
            stmts.golang_name = convert_to_golang(name)
            if stmts.golang_name == 'PeerType':
                stmts.golang_name = 'PeerTypeDef'
            child_map[name] = stmts

    ctx.golang_typedef_map[prefix] = child_map
    if ctx.prefix_rel[prefix] != prefix:
        ctx.golang_typedef_map[ctx.prefix_rel[prefix]] = child_map


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

        if stmt.path in _typedef_exclude:
            continue

        # skip identityref type because currently skip identity
        if get_type_spec(stmt) == 'identityref':
            continue

        type_name_org = name
        type_name = stmt.golang_name
        if type_name in emitted_type_names:
            warn = "warning %s: %s has already been emitted from %s.\n"\
                   % (prefix+":"+type_name_org, type_name_org,
                      emitted_type_names[type_name])
            sys.stderr.write(warn)
            continue

        emitted_type_names[type_name] = prefix+":"+type_name_org

        t = stmt.search_one('type')
        o = StringIO.StringIO()

        if t.arg == 'enumeration':
            print >> o, '// typedef for typedef %s:%s'\
                        % (prefix, type_name_org)
            print >> o, 'type %s int' % (type_name)

            const_prefix = convert_const_prefix(type_name_org)
            print >> o, 'const ('

            already_added_iota = False
            already_added_type = False
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

                t = type_name if not already_added_type else ""
                already_added_type = True

                print >> o, ' %s_%s %s%s' % (const_prefix, enum_name, t, enum_value)
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


def is_leafref(s):
    return s.arg in ['leafref']


def is_leaf(s):
    return s.keyword in ['leaf']


def is_leaflist(s):
    return s.keyword in ['leaf-list']


def is_list(s):
    return s.keyword in ['list']


def is_container(s):
    return s.keyword in ['container']


def is_case(s):
    return s.keyword in ['case']


def is_choice(s):
    return s.keyword in ['choice']


def is_builtin_type(t):
    return t.arg in _type_builtin


def is_translation_required(t):
    return t.arg in _type_translation_map.keys()


_type_translation_map = {
    'union': 'string',
    'enumeration': 'uint32',
    'decimal64': 'float64',
    'boolean': 'bool',
    'empty': 'bool',
    'inet:ip-address': 'net.IP',
    'inet:ip-prefix': 'string',
    'inet:ipv4-address': 'net.IP',
    'inet:as-number': 'uint32',
    'bgp-set-community-option-type' : 'string',
    'identityref' : 'string',
    'inet:port-number': 'uint16',
    'yang:timeticks': 'int64',
    'ptypes:install-protocol-type': 'string',
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


_module_excluded = ["ietf-inet-types",
                    "ietf-yang-types",
                    ]

_path_exclude = ["/bgp:bgp/bgp:neighbors/bgp:neighbor/bgp:transport/bgp:config/bgp:local-address",
                 "/bgp:bgp/bgp:neighbors/bgp:neighbor/bgp:transport/bgp:state/bgp:local-address",
                 "/rpol:routing-policy/rpol:defined-sets/rpol:neighbor-sets/rpol:neighbor-set/rpol:neighbor",
                 "/rpol:routing-policy/rpol:defined-sets/bgp-pol:bgp-defined-sets/bgp-pol:community-sets/bgp-pol:community-set/bgp-pol:community-member",
                 "/rpol:routing-policy/rpol:defined-sets/bgp-pol:bgp-defined-sets/bgp-pol:ext-community-sets/bgp-pol:ext-community-set/bgp-pol:ext-community-member",
                 "/rpol:routing-policy/rpol:defined-sets/bgp-pol:bgp-defined-sets/bgp-pol:as-path-sets/bgp-pol:as-path-set/bgp-pol:as-path-set-member"]

_typedef_exclude =["/bgp-types:bgp-origin-attr-type"]

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
