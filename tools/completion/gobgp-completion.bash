#!/bin/bash

__debug()
{
    if [[ -n ${BASH_COMP_DEBUG_FILE} ]]; then
        echo "$*" >> "${BASH_COMP_DEBUG_FILE}"
    fi
}

# Homebrew on Macs have version 1.3 of bash-completion which doesn't include
# _init_completion. This is a very minimal version of that function.
__my_init_completion()
{
    COMPREPLY=()
    _get_comp_words_by_ref cur prev words cword
}

__index_of_word()
{
    local w word=$1
    shift
    index=0
    for w in "$@"; do
        [[ $w = "$word" ]] && return
        index=$((index+1))
    done
    index=-1
}

__contains_word()
{
    local w word=$1; shift
    for w in "$@"; do
        [[ $w = "$word" ]] && return
    done
    return 1
}

__handle_reply()
{
    __debug "${FUNCNAME}"
    case $cur in
        -*)
            compopt -o nospace
            local allflags
            if [ ${#must_have_one_flag[@]} -ne 0 ]; then
                allflags=("${must_have_one_flag[@]}")
            else
                allflags=("${flags[*]} ${two_word_flags[*]}")
            fi
            COMPREPLY=( $(compgen -W "${allflags[*]}" -- "$cur") )
            [[ $COMPREPLY == *= ]] || compopt +o nospace
            return 0;
            ;;
    esac

    # check if we are handling a flag with special work handling
    local index
    __index_of_word "${prev}" "${flags_with_completion[@]}"
    if [[ ${index} -ge 0 ]]; then
        ${flags_completion[${index}]}
        return
    fi

    # we are parsing a flag and don't have a special handler, no completion
    if [[ ${cur} != "${words[cword]}" ]]; then
        return
    fi

    local completions
    if [[ ${#must_have_one_flag[@]} -ne 0 ]]; then
        completions=("${must_have_one_flag[@]}")
    elif [[ ${#must_have_one_noun[@]} -ne 0 ]]; then
        completions=("${must_have_one_noun[@]}")
    else
        completions=("${commands[@]}")
    fi
    COMPREPLY=( $(compgen -W "${completions[*]}" -- "$cur") )

    if [[ ${#COMPREPLY[@]} -eq 0 ]]; then
        declare -F __custom_func >/dev/null && __custom_func
    fi
}

# The arguments should be in the form "ext1|ext2|extn"
__handle_filename_extension_flag()
{
    local ext="$1"
    _filedir "@(${ext})"
}

__handle_subdirs_in_dir_flag()
{
    local dir="$1"
    pushd "${dir}" >/dev/null 2>&1 && _filedir -d && popd >/dev/null 2>&1
}

__handle_flag()
{
    __debug "${FUNCNAME}: c is $c words[c] is ${words[c]}"

    # if a command required a flag, and we found it, unset must_have_one_flag()
    local flagname=${words[c]}
    # if the word contained an =
    if [[ ${words[c]} == *"="* ]]; then
        flagname=${flagname%=*} # strip everything after the =
        flagname="${flagname}=" # but put the = back
    fi
    __debug "${FUNCNAME}: looking for ${flagname}"
    if __contains_word "${flagname}" "${must_have_one_flag[@]}"; then
        must_have_one_flag=()
    fi

    # skip the argument to a two word flag
    if __contains_word "${words[c]}" "${two_word_flags[@]}"; then
        c=$((c+1))
        # if we are looking for a flags value, don't show commands
        if [[ $c -eq $cword ]]; then
            commands=()
        fi
    fi

    # skip the flag itself
    c=$((c+1))

}

__handle_noun()
{
    __debug "${FUNCNAME}: c is $c words[c] is ${words[c]}"

    if __contains_word "${words[c]}" "${must_have_one_noun[@]}"; then
        must_have_one_noun=()
    fi

    nouns+=("${words[c]}")
    c=$((c+1))
}

__handle_command()
{
    __debug "${FUNCNAME}: c is $c words[c] is ${words[c]}"

    local next_command
    if [[ -n ${last_command} ]]; then
        next_command="_${last_command}_${words[c]}"
    else
        next_command="_${words[c]}"
    fi
    c=$((c+1))
    __debug "${FUNCNAME}: looking for ${next_command}"
    declare -F $next_command >/dev/null && $next_command
}

__handle_word()
{
    if [[ $c -ge $cword ]]; then
        __handle_reply
	return
    fi
    __debug "${FUNCNAME}: c is $c words[c] is ${words[c]}"
    if [[ "${words[c]}" == -* ]]; then
	__handle_flag
    elif __contains_word "${words[c]}" "${commands[@]}"; then
        __handle_command
    else
        __handle_noun
    fi
    __handle_word
}

_gobgp_global_rib_add()
{
    last_command="gobgp_global_rib_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_rib_del()
{
    last_command="gobgp_global_rib_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_rib()
{
    last_command="gobgp_global_rib"
    commands=()
    commands+=("add")
    commands+=("del")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_in_add()
{
    last_command="gobgp_global_policy_in_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_in_del()
{
    last_command="gobgp_global_policy_in_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_in_set()
{
    last_command="gobgp_global_policy_in_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_in()
{
    last_command="gobgp_global_policy_in"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_import_add()
{
    last_command="gobgp_global_policy_import_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_import_del()
{
    last_command="gobgp_global_policy_import_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_import_set()
{
    last_command="gobgp_global_policy_import_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_import()
{
    last_command="gobgp_global_policy_import"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_export_add()
{
    last_command="gobgp_global_policy_export_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_export_del()
{
    last_command="gobgp_global_policy_export_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_export_set()
{
    last_command="gobgp_global_policy_export_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy_export()
{
    last_command="gobgp_global_policy_export"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global_policy()
{
    last_command="gobgp_global_policy"
    commands=()
    commands+=("in")
    commands+=("import")
    commands+=("export")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global()
{
    last_command="gobgp_global"
    commands=()
    commands+=("rib")
    commands+=("policy")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_neighbor()
{
    last_command="gobgp_neighbor"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
    flags+=("--transport=")
    two_word_flags+=("-t")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_vrf_add()
{
    last_command="gobgp_vrf_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_vrf_del()
{
    last_command="gobgp_vrf_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_vrf()
{
    last_command="gobgp_vrf"
    commands=()
    commands+=("add")
    commands+=("del")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_prefix_add()
{
    last_command="gobgp_policy_prefix_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_prefix_del()
{
    last_command="gobgp_policy_prefix_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_prefix_set()
{
    last_command="gobgp_policy_prefix_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_prefix()
{
    last_command="gobgp_policy_prefix"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_neighbor_add()
{
    last_command="gobgp_policy_neighbor_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_neighbor_del()
{
    last_command="gobgp_policy_neighbor_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_neighbor_set()
{
    last_command="gobgp_policy_neighbor_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_neighbor()
{
    last_command="gobgp_policy_neighbor"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_as-path_add()
{
    last_command="gobgp_policy_as-path_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_as-path_del()
{
    last_command="gobgp_policy_as-path_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_as-path_set()
{
    last_command="gobgp_policy_as-path_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_as-path()
{
    last_command="gobgp_policy_as-path"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_community_add()
{
    last_command="gobgp_policy_community_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_community_del()
{
    last_command="gobgp_policy_community_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_community_set()
{
    last_command="gobgp_policy_community_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_community()
{
    last_command="gobgp_policy_community"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_ext-community_add()
{
    last_command="gobgp_policy_ext-community_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_ext-community_del()
{
    last_command="gobgp_policy_ext-community_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_ext-community_set()
{
    last_command="gobgp_policy_ext-community_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_ext-community()
{
    last_command="gobgp_policy_ext-community"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_statement_add()
{
    last_command="gobgp_policy_statement_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_statement_del()
{
    last_command="gobgp_policy_statement_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_statement()
{
    last_command="gobgp_policy_statement"
    commands=()
    commands+=("add")
    commands+=("del")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_add()
{
    last_command="gobgp_policy_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_del()
{
    last_command="gobgp_policy_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_set()
{
    last_command="gobgp_policy_set"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy()
{
    last_command="gobgp_policy"
    commands=()
    commands+=("prefix")
    commands+=("neighbor")
    commands+=("as-path")
    commands+=("community")
    commands+=("ext-community")
    commands+=("statement")
    commands+=("add")
    commands+=("del")
    commands+=("set")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_monitor_global_rib()
{
    last_command="gobgp_monitor_global_rib"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_monitor_global()
{
    last_command="gobgp_monitor_global"
    commands=()
    commands+=("rib")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_monitor_neighbor()
{
    last_command="gobgp_monitor_neighbor"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_monitor()
{
    last_command="gobgp_monitor"
    commands=()
    commands+=("global")
    commands+=("neighbor")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_mrt_dump_rib_global()
{
    last_command="gobgp_mrt_dump_rib_global"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_mrt_dump_rib_neighbor()
{
    last_command="gobgp_mrt_dump_rib_neighbor"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_mrt_dump_rib()
{
    last_command="gobgp_mrt_dump_rib"
    commands=()
    commands+=("global")
    commands+=("neighbor")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_mrt_dump()
{
    last_command="gobgp_mrt_dump"
    commands=()
    commands+=("rib")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--format=")
    two_word_flags+=("-f")
    flags+=("--outdir=")
    two_word_flags+=("-o")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_mrt_inject_global()
{
    last_command="gobgp_mrt_inject_global"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_mrt_inject()
{
    last_command="gobgp_mrt_inject"
    commands=()
    commands+=("global")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_mrt()
{
    last_command="gobgp_mrt"
    commands=()
    commands+=("dump")
    commands+=("inject")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_rpki_server()
{
    last_command="gobgp_rpki_server"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_rpki_table()
{
    last_command="gobgp_rpki_table"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_rpki()
{
    last_command="gobgp_rpki"
    commands=()
    commands+=("server")
    commands+=("table")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()


    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp()
{
    last_command="gobgp"
    commands=()
    commands+=("global")
    commands+=("neighbor")
    commands+=("vrf")
    commands+=("policy")
    commands+=("monitor")
    commands+=("mrt")
    commands+=("rpki")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--bash-cmpl-file=")
    flags+=("--debug")
    flags+=("-d")
    flags+=("--gen-cmpl")
    flags+=("-c")
    flags+=("--host=")
    two_word_flags+=("-u")
    flags+=("--json")
    flags+=("-j")
    flags+=("--port=")
    two_word_flags+=("-p")
    flags+=("--quiet")
    flags+=("-q")

    must_have_one_flag=()
    must_have_one_noun=()
}

__start_gobgp()
{
    local cur prev words cword
    if declare -F _init_completions >/dev/null 2>&1; then
        _init_completion -s || return
    else
        __my_init_completion || return
    fi

    local c=0
    local flags=()
    local two_word_flags=()
    local flags_with_completion=()
    local flags_completion=()
    local commands=("gobgp")
    local must_have_one_flag=()
    local must_have_one_noun=()
    local last_command
    local nouns=()

    __handle_word
}

complete -F __start_gobgp gobgp
# ex: ts=4 sw=4 et filetype=sh
