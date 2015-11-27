#!/bin/bash

__gobgp_q()
{
    gobgp 2>/dev/null "$@"
}

__gobgp_q_neighbor()
{
    neighbors=( $(__gobgp_q $url $port --quiet neighbor) )
    case "${neighbors[*]}" in
        "grpc: timed out"* | "rpc error:"* )
            req_faild="True"
            return
        ;;
    esac
    for n in ${neighbors[*]}; do
        commands+=($n)
    done
    searched="True"
}

__gobgp_q_vrf()
{
    vrfs=( $(__gobgp_q $url $port --quiet vrf) )
    case "${vrfs[*]}" in
        "grpc: timed out"* | "rpc error:"* )
            req_faild="True"
            return
        ;;
    esac
    for n in ${vrfs[*]}; do
        commands+=($n)
    done
    searched="True"
}

__gobgp_q_policy()
{
    local parg=$1
    policies=( $(__gobgp_q $url $port --quiet policy $parg) )
    case "${policies[*]}" in
        "grpc: timed out"* | "rpc error:"* )
            req_faild="True"
            return
        ;;
    esac
    for ps in ${policies[*]}; do
        commands+=($ps)
    done
    searched="True"
}

__gobgp_q_statement()
{
    local pol=$1
    statements=( $(__gobgp_q $url $port --quiet policy statement ) )
    case "${statements[*]}" in
        "grpc: timed out"* | "rpc error:"* )
            req_faild="True"
            return
        ;;
    esac
    for sts in ${statements[*]}; do
        commands+=($sts)
    done
    searched="True"
}

__handle_gobgp_command()
{
    if [[ ${searched} == "True" ]]; then
        case "${last_command}" in
            gobgp_neighbor )
                next_command="_${last_command}_addr"
            ;;
            gobgp_policy_prefix_* | gobgp_policy_neighbor_* | gobgp_policy_as-path_* | gobgp_policy_community_* | gobgp_policy_ext-community_* )
                next_command="__gobgp_null"
            ;;
            gobgp_policy_del | gobgp_policy_set )
                next_command="__gobgp_null"
            ;;
            gobgp_policy_statement )
                if [[ ${words[c]} == "del" || ${words[c]} == "add" ]]; then
                    return
                fi
                next_command="_gobgp_policy_statement_sname"
            ;;
            gobgp_policy_statement_del )
                next_command="__gobgp_null"
            ;;
            *_condition_prefix | *_condition_neighbor | *_condition_as-path | *_condition_community  | *_ext-condition_community )
                next_command="__gobgp_null"
            ;;
            gobgp_vrf )
                if [[ ${words[c]} == "del" || ${words[c]} == "add" ]]; then
                    return
                fi
                next_command="_global_vrf_vname"
            ;;
            gobgp_vrf_del )
                next_command="__gobgp_null"
            ;;
            gobgp_mrt_dump_rib_neighbor )
                next_command="__gobgp_null"
            ;;
            gobgp_monitor_neighbor )
                next_command="__gobgp_null"
            ;;
        esac
        through="True"
    fi
}

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
            if [[ $(type -t compopt) = "builtin" ]]; then
                compopt -o nospace
            fi
            local allflags
            if [ ${#must_have_one_flag[@]} -ne 0 ]; then
                allflags=("${must_have_one_flag[@]}")
            else
                allflags=("${flags[*]} ${two_word_flags[*]}")
            fi
            COMPREPLY=( $(compgen -W "${allflags[*]}" -- "$cur") )
            if [[ $(type -t compopt) = "builtin" ]]; then
                [[ $COMPREPLY == *= ]] || compopt +o nospace
            fi
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

    if [ ${words[(c-1)]} == "-u" ]; then
        url="-u ${words[(c)]}"
    fi
    if [ ${words[(c-1)]} == "-p" ]; then
        port="-p ${words[(c)]}"
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
    # echo "${FUNCNAME}: c is $c words[c] is ${words[c]} searched is ${searched} through ${through}"
    next_command=""
    through="False"
    __handle_gobgp_command
    searched="False"
    if [[ ${through} == "False" ]]; then
        if [[ -n ${last_command} ]]; then
            next_command="_${last_command}_${words[c]}"
        else
            next_command="_${words[c]}"
        fi
    fi

    c=$((c+1))
    __debug "${FUNCNAME}: looking for ${next_command}"
    # echo "${FUNCNAME}: looking for ${next_command} searched is ${searched} through ${through}"
    declare -F $next_command >/dev/null && $next_command

    if [[ ${req_faild} == "True" ]]; then
        next_command="__gobgp_null"
    fi
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

__gobgp_null()
{
    last_command="gobgp_null"
    commands=()

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

_gobgp_global_rib_add()
{
    last_command="gobgp_global_rib_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
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

_gobgp_global_rib_del()
{
    last_command="gobgp_global_rib_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
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

_gobgp_global_policy_in_add()
{
    last_command="gobgp_global_policy_in_add"
    commands=()

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

_gobgp_global_policy_in_del()
{
    last_command="gobgp_global_policy_in_del"
    commands=()

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

_gobgp_global_policy_in_set()
{
    last_command="gobgp_global_policy_in_set"
    commands=()

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

_gobgp_global_policy_import_add()
{
    last_command="gobgp_global_policy_import_add"
    commands=()

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

_gobgp_global_policy_import_del()
{
    last_command="gobgp_global_policy_import_del"
    commands=()

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

_gobgp_global_policy_import_set()
{
    last_command="gobgp_global_policy_import_set"
    commands=()

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

_gobgp_global_policy_export_add()
{
    last_command="gobgp_global_policy_export_add"
    commands=()

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

_gobgp_global_policy_export_del()
{
    last_command="gobgp_global_policy_export_del"
    commands=()

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

_gobgp_global_policy_export_set()
{
    last_command="gobgp_global_policy_export_set"
    commands=()

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

_gobgp_neighbor_addr_local()
{
    last_command="gobgp_neighbor_addr_local"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
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

_gobgp_neighbor_addr_adj-in()
{
    last_command="gobgp_neighbor_addr_adj-in"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
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

_gobgp_neighbor_addr_adj-out()
{
    last_command="gobgp_neighbor_addr_adj-out"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
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

_gobgp_neighbor_addr_reset()
{
    last_command="gobgp_neighbor_addr_reset"
    commands=()

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

_gobgp_neighbor_addr_softreset()
{
    last_command="gobgp_neighbor_addr_softreset"
    commands=()

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

_gobgp_neighbor_addr_softresetin()
{
    last_command="gobgp_neighbor_addr_softresetin"
    commands=()

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

_gobgp_neighbor_addr_softresetout()
{
    last_command="gobgp_neighbor_addr_softresetout"
    commands=()

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

_gobgp_neighbor_addr_shutdown()
{
    last_command="gobgp_neighbor_addr_shutdown"
    commands=()

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

_gobgp_neighbor_addr_enable()
{
    last_command="gobgp_neighbor_addr_enable"
    commands=()

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

_gobgp_neighbor_addr_disable()
{
    last_command="gobgp_neighbor_addr_disable"
    commands=()

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

_gobgp_neighbor_addr_policy_in_add()
{
    last_command="gobgp_neighbor_addr_policy_in_add"
    commands=()

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

_gobgp_neighbor_addr_policy_in_del()
{
    last_command="gobgp_neighbor_addr_policy_in_del"
    commands=()

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

_gobgp_neighbor_addr_policy_in_set()
{
    last_command="gobgp_neighbor_addr_policy_in_set"
    commands=()

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

_gobgp_neighbor_addr_policy_in()
{
    last_command="gobgp_neighbor_addr_policy_in"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

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

_gobgp_neighbor_addr_policy_import_add()
{
    last_command="gobgp_neighbor_addr_policy_import_add"
    commands=()

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

_gobgp_neighbor_addr_policy_import_del()
{
    last_command="gobgp_neighbor_addr_policy_import_del"
    commands=()

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

_gobgp_neighbor_addr_policy_import_set()
{
    last_command="gobgp_neighbor_addr_policy_import_set"
    commands=()

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

_gobgp_neighbor_addr_policy_import()
{
    last_command="gobgp_neighbor_addr_policy_import"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

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

_gobgp_neighbor_addr_policy_export_add()
{
    last_command="gobgp_neighbor_addr_policy_export_add"
    commands=()

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

_gobgp_neighbor_addr_policy_export_del()
{
    last_command="gobgp_neighbor_addr_policy_export_del"
    commands=()

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

_gobgp_neighbor_addr_policy_export_set()
{
    last_command="gobgp_neighbor_addr_policy_export_set"
    commands=()

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

_gobgp_neighbor_addr_policy_export()
{
    last_command="gobgp_neighbor_addr_policy_export"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

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

_gobgp_neighbor_addr_policy()
{
    last_command="gobgp_neighbor_addr_policy"
    commands=()
    commands+=("in")
    commands+=("import")
    commands+=("export")

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

_gobgp_neighbor_addr()
{
    last_command="gobgp_neighbor_addr"
    commands=()
    commands+=("local")
    commands+=("adj-in")
    commands+=("adj-out")
    commands+=("reset")
    commands+=("softreset")
    commands+=("softresetin")
    commands+=("softresetout")
    commands+=("shutdown")
    commands+=("enable")
    commands+=("disable")
    commands+=("policy")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
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
    __gobgp_q_neighbor
}

_global_vrf_vname_rib_del()
{
    last_command="global_vrf_vname_rib_del"
    commands=()

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

_global_vrf_vname_rib()
{
    last_command="global_vrf_vname_rib"
    commands=()
    commands+=("del")

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

_global_vrf_vname()
{
    last_command="global_vrf_vname"
    commands=()
    commands+=("rib")

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

_gobgp_vrf_add()
{
    last_command="gobgp_vrf_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
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

_gobgp_vrf_del()
{
    last_command="gobgp_vrf_del"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
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
    __gobgp_q_vrf
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
    __gobgp_q_vrf
}

_gobgp_policy_prefix_add()
{
    last_command="gobgp_policy_prefix_add"
    commands=()

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

_gobgp_policy_prefix_del()
{
    last_command="gobgp_policy_prefix_del"
    commands=()

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
    __gobgp_q_policy "prefix"
}

_gobgp_policy_prefix_set()
{
    last_command="gobgp_policy_prefix_set"
    commands=()

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
    __gobgp_q_policy "prefix"
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

_gobgp_policy_neighbor_add()
{
    last_command="gobgp_policy_neighbor_add"
    commands=()

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

_gobgp_policy_neighbor_del()
{
    last_command="gobgp_policy_neighbor_del"
    commands=()

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
    __gobgp_q_policy "neighbor"
}

_gobgp_policy_neighbor_set()
{
    last_command="gobgp_policy_neighbor_set"
    commands=()

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
    __gobgp_q_policy "neighbor"
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

_gobgp_policy_as-path_add()
{
    last_command="gobgp_policy_as-path_add"
    commands=()

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

_gobgp_policy_as-path_del()
{
    last_command="gobgp_policy_as-path_del"
    commands=()

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
    __gobgp_q_policy "as-path"
}

_gobgp_policy_as-path_set()
{
    last_command="gobgp_policy_as-path_set"
    commands=()

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
    __gobgp_q_policy "as-path"
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

_gobgp_policy_community_add()
{
    last_command="gobgp_policy_community_add"
    commands=()

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

_gobgp_policy_community_del()
{
    last_command="gobgp_policy_community_del"
    commands=()

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
    __gobgp_q_policy "community"
}

_gobgp_policy_community_set()
{
    last_command="gobgp_policy_community_set"
    commands=()

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
    __gobgp_q_policy "community"
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

_gobgp_policy_ext-community_add()
{
    last_command="gobgp_policy_ext-community_add"
    commands=()

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

_gobgp_policy_ext-community_del()
{
    last_command="gobgp_policy_ext-community_del"
    commands=()

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
    __gobgp_q_policy "ext-community"
}

_gobgp_policy_ext-community_set()
{
    last_command="gobgp_policy_ext-community_set"
    commands=()

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
    __gobgp_q_policy "ext-community"
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

_gobgp_policy_statement_sname_ope_condition_prefix()
{
    last_command="gobgp_policy_statement_sname_ope_condition_prefix"
    commands=()

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
    __gobgp_q_policy "prefix"
}

_gobgp_policy_statement_sname_ope_condition_neighbor()
{
    last_command="gobgp_policy_statement_sname_ope_condition_neighbor"
    commands=()

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
    __gobgp_q_policy "neighbor"
}

_gobgp_policy_statement_sname_ope_condition_as-path()
{
    last_command="gobgp_policy_statement_sname_ope_condition_as-path"
    commands=()

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
    __gobgp_q_policy "as-path"
}

_gobgp_policy_statement_sname_ope_condition_community()
{
    last_command="gobgp_policy_statement_sname_ope_condition_community"
    commands=()

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
    __gobgp_q_policy "community"
}

_gobgp_policy_statement_sname_ope_condition_ext-community()
{
    last_command="gobgp_policy_statement_sname_ope_condition_ext-community"
    commands=()

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
    __gobgp_q_policy "ext-community"
}

_gobgp_policy_statement_sname_ope_condition_as-path-length()
{
    last_command="gobgp_policy_statement_sname_ope_condition_as-path-length"
    commands=()

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

_gobgp_policy_statement_sname_ope_condition_rpki_valid()
{
    last_command="gobgp_policy_statement_sname_ope_condition_rpki_valid"
    commands=()

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

_gobgp_policy_statement_sname_ope_condition_rpki_invalid()
{
    last_command="gobgp_policy_statement_sname_ope_condition_rpki_invalid"
    commands=()

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

_gobgp_policy_statement_sname_ope_condition_rpki_not-found()
{
    last_command="gobgp_policy_statement_sname_ope_condition_rpki_not-found"
    commands=()

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

_gobgp_policy_statement_sname_ope_condition_rpki()
{
    last_command="gobgp_policy_statement_sname_ope_condition_rpki"
    commands=()
    commands+=("valid")
    commands+=("invalid")
    commands+=("not-found")

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


_gobgp_policy_statement_sname_ope_condition()
{
    last_command="gobgp_policy_statement_sname_ope_condition"
    commands=()
    commands+=("prefix")
    commands+=("neighbor")
    commands+=("as-path")
    commands+=("community")
    commands+=("ext-community")
    commands+=("as-path-length")
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

_gobgp_policy_statement_sname_ope_action_reject()
{
    last_command="gobgp_policy_statement_sname_ope_action_reject"
    commands=()

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

_gobgp_policy_statement_sname_ope_action_accept()
{
    last_command="gobgp_policy_statement_sname_ope_action_accept"
    commands=()

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

_gobgp_policy_statement_sname_ope_action_communities_add()
{
    last_command="gobgp_policy_statement_sname_ope_action_communities_add"
    commands=()

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

_gobgp_policy_statement_sname_ope_action_communities_remove()
{
    last_command="gobgp_policy_statement_sname_ope_action_communities_remove"
    commands=()

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

_gobgp_policy_statement_sname_ope_action_communities_replace()
{
    last_command="gobgp_policy_statement_sname_ope_action_communities_replace"
    commands=()

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

_gobgp_policy_statement_sname_ope_action_communities()
{
    last_command="gobgp_policy_statement_sname_ope_action_communities"
    commands=()
    commands+=("add")
    commands+=("remove")
    commands+=("replace")

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

_gobgp_policy_statement_sname_ope_action_community()
{
    _gobgp_policy_statement_sname_ope_action_communities
}

_gobgp_policy_statement_sname_ope_action_ext-community()
{
    _gobgp_policy_statement_sname_ope_action_communities
}

_gobgp_policy_statement_sname_ope_action_med_add()
{
    last_command="gobgp_policy_statement_sname_ope_action_med_add"
    commands=()

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

_gobgp_policy_statement_sname_ope_action_med_sub()
{
    last_command="gobgp_policy_statement_sname_ope_action_med_sub"
    commands=()

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

_gobgp_policy_statement_sname_ope_action_med_set()
{
    last_command="gobgp_policy_statement_sname_ope_action_med_set"
    commands=()

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

_gobgp_policy_statement_sname_ope_action_med()
{
    last_command="gobgp_policy_statement_sname_ope_action_med"
    commands=()
    commands+=("add")
    commands+=("sub")
    commands+=("set")

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

_gobgp_policy_statement_sname_ope_action_as-prepend()
{
    last_command="gobgp_policy_statement_sname_ope_action_as-prepend"
    commands=()

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

_gobgp_policy_statement_sname_ope_action()
{
    last_command="gobgp_policy_statement_sname_ope_action"
    commands=()
    commands+=("reject")
    commands+=("accept")
    commands+=("community")
    commands+=("ext-community")
    commands+=("med")
    commands+=("as-prepend")

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

_gobgp_policy_statement_sname_ope()
{
    last_command="gobgp_policy_statement_sname_ope"
    commands=()
    commands+=("condition")
    commands+=("action")

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

_gobgp_policy_statement_sname_add()
{
    _gobgp_policy_statement_sname_ope
}

_gobgp_policy_statement_sname_del()
{
    _gobgp_policy_statement_sname_ope
}

_gobgp_policy_statement_sname_set()
{
    _gobgp_policy_statement_sname_ope
}

_gobgp_policy_statement_sname()
{
    last_command="gobgp_policy_statement_sname"
    commands=()
    commands+=("add")
    commands+=("del")
    commands+=("set")

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

_gobgp_policy_statement_add()
{
    last_command="gobgp_policy_statement_add"
    commands=()

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

_gobgp_policy_statement_del()
{
    last_command="gobgp_policy_statement_del"
    commands=()

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
    __gobgp_q_statement
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
    __gobgp_q_statement
}

_gobgp_policy_add()
{
    last_command="gobgp_policy_add"
    commands=()

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

_gobgp_policy_del()
{
    last_command="gobgp_policy_del"
    commands=()

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
    __gobgp_q_policy ""
}

_gobgp_policy_set()
{
    last_command="gobgp_policy_set"
    commands=()

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
    __gobgp_q_policy ""
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

_gobgp_monitor_global()
{
    last_command="gobgp_monitor_global"
    commands=()
    commands+=("rib")

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

_gobgp_monitor_neighbor()
{
    last_command="gobgp_monitor_neighbor"
    commands=()

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
    __gobgp_q_neighbor
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

_gobgp_mrt_dump_rib_global()
{
    last_command="gobgp_mrt_dump_rib_global"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
    flags+=("--bash-cmpl-file=")
    flags+=("--debug")
    flags+=("-d")
    flags+=("--format=")
    two_word_flags+=("-f")
    flags+=("--gen-cmpl")
    flags+=("-c")
    flags+=("--host=")
    two_word_flags+=("-u")
    flags+=("--json")
    flags+=("-j")
    flags+=("--outdir=")
    two_word_flags+=("-o")
    flags+=("--port=")
    two_word_flags+=("-p")
    flags+=("--quiet")
    flags+=("-q")

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

    flags+=("--address-family=")
    two_word_flags+=("-a")
    flags+=("--bash-cmpl-file=")
    flags+=("--debug")
    flags+=("-d")
    flags+=("--format=")
    two_word_flags+=("-f")
    flags+=("--gen-cmpl")
    flags+=("-c")
    flags+=("--host=")
    two_word_flags+=("-u")
    flags+=("--json")
    flags+=("-j")
    flags+=("--outdir=")
    two_word_flags+=("-o")
    flags+=("--port=")
    two_word_flags+=("-p")
    flags+=("--quiet")
    flags+=("-q")

    must_have_one_flag=()
    must_have_one_noun=()
    __gobgp_q_neighbor
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
    flags+=("--bash-cmpl-file=")
    flags+=("--debug")
    flags+=("-d")
    flags+=("--format=")
    two_word_flags+=("-f")
    flags+=("--gen-cmpl")
    flags+=("-c")
    flags+=("--host=")
    two_word_flags+=("-u")
    flags+=("--json")
    flags+=("-j")
    flags+=("--outdir=")
    two_word_flags+=("-o")
    flags+=("--port=")
    two_word_flags+=("-p")
    flags+=("--quiet")
    flags+=("-q")

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

_gobgp_mrt_inject_global()
{
    last_command="gobgp_mrt_inject_global"
    commands=()

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

_gobgp_mrt_inject()
{
    last_command="gobgp_mrt_inject"
    commands=()
    commands+=("global")

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

_gobgp_mrt_update_enable()
{
    last_command="gobgp_mrt_update_enable"
    commands=()

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

_gobgp_mrt_update_disable()
{
    last_command="gobgp_mrt_update_disable"
    commands=()

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

_gobgp_mrt_update_reset()
{
    last_command="gobgp_mrt_update_reset"
    commands=()

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

_gobgp_mrt_update_rotate()
{
    last_command="gobgp_mrt_update_rotate"
    commands=()

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

_gobgp_mrt_update()
{
    last_command="gobgp_mrt_update"
    commands=()
    commands+=("enable")
    commands+=("disable")
    commands+=("reset")
    commands+=("rotate")

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

_gobgp_mrt()
{
    last_command="gobgp_mrt"
    commands=()
    commands+=("dump")
    commands+=("inject")
    commands+=("update")

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

_gobgp_rpki_enable()
{
    last_command="gobgp_rpki_enable"
    commands=()

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

_gobgp_rpki_server()
{
    last_command="gobgp_rpki_server"
    commands=()

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

_gobgp_rpki()
{
    last_command="gobgp_rpki"
    commands=()
    commands+=("enable")
    commands+=("server")
    commands+=("table")

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

_gobgp()
{
    url=""
    port=""
    q_type=""
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
    if declare -F _init_completion >/dev/null 2>&1; then
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

    req_faild="False"
    searched="False"
    through="False"
    __handle_word
}

if [[ $(type -t compopt) = "builtin" ]]; then
    complete -F __start_gobgp gobgp
else
    complete -o nospace -F __start_gobgp gobgp
fi

# ex: ts=4 sw=4 et filetype=sh
