#!/bin/bash

__gobgp_q() {
    gobgp 2>/dev/null "$@"
}

__gobgp_q_neighbor() {
    neighbors=( $(__gobgp_q $url $port --quiet $q_type) )
    for n in ${neighbors[*]}; do
        commands+=($n)
    done
    neighbor_searched="True"
    last_command="gobgp_neighbor"
}

__gobgp_q_policy() {
    policies=( $(__gobgp_q $url $port --quiet policy $q_type) )
    for ps in ${policies[*]}; do
        commands+=($ps)
    done
    if [[ ${want_state} == "True" ]]; then
        want_state="False"
    fi
    if [[ ${last_command} == "gobgp_policy_routepolicy_add" ]]; then
        want_state="True"
    else
        policy_searched="True"
    fi
}


__debug()
{
    if [[ -n ${BASH_COMP_DEBUG_FILE} ]]; then
        echo "$*" >> "${BASH_COMP_DEBUG_FILE}"
    fi
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

    local next_command
    if [[ -n ${last_command} ]]; then
        next_command="_${last_command}_${words[c]}"
    else
        next_command="_${words[c]}"
    fi

    if [[ ${last_command} == "gobgp_neighbor_someone" ]]; then
        commands=()
    fi

    if [[ ${neighbor_searched} == "True" ]]; then
        next_command="_${last_command}_someone"
    fi

    if [[ ${policy_searched} == "True" ]]; then
        commands=()
    fi
    if [[ ${want_state} == "True" ]]; then
        routepolicy="${words[c]}"
        next_command="_${last_command}_state"
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
    # __debug "${FUNCNAME}: c is $c words[c] is ${words[c]}"
    # echo "${FUNCNAME}: c is $c words[c] is ${words[c]} cword is ${cword}"
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

    flags+=("--help")
    flags+=("-h")

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

    flags+=("--help")
    flags+=("-h")

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
    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_global()
{
    last_command="gobgp_global"
    commands=()
    commands+=("rib")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_neighbor_someone()
{
    last_command="gobgp_neighbor_someone"
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

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--address-family=")
    two_word_flags+=("-a")
    flags+=("--help")
    flags+=("-h")

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
    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
    q_type="neighbor"
    __gobgp_q_neighbor
}

_gobgp_policy_prefix_add()
{
    last_command="gobgp_policy_prefix_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_prefix_del_all()
{
    last_command="gobgp_policy_prefix_del_all"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_prefix_del()
{
    last_command="gobgp_policy_prefix_del"
    commands=()
    commands+=("all")
    q_type="prefix"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_prefix()
{
    last_command="gobgp_policy_prefix"
    commands=()
    commands+=("add")
    commands+=("del")
    q_type="prefix"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

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

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_neighbor_del_all()
{
    last_command="gobgp_policy_neighbor_del_all"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_neighbor_del()
{
    last_command="gobgp_policy_neighbor_del"
    commands=()
    commands+=("all")
     q_type="neighbor"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_neighbor()
{
    last_command="gobgp_policy_neighbor"
    commands=()
    commands+=("add")
    commands+=("del")
     q_type="neighbor"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_aspath_add()
{
    last_command="gobgp_policy_aspath_add"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_aspath_del_all()
{
    last_command="gobgp_policy_aspath_del_all"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_aspath_del()
{
    last_command="gobgp_policy_aspath_del"
    commands=()
    commands+=("all")
    q_type="aspath"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_aspath()
{
    last_command="gobgp_policy_aspath"
    commands=()
    commands+=("add")
    commands+=("del")
    q_type="aspath"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

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

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_community_del_all()
{
    last_command="gobgp_policy_community_del_all"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_community_del()
{
    last_command="gobgp_policy_community_del"
    commands=()
    commands+=("all")
    q_type="community"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_community()
{
    last_command="gobgp_policy_community"
    commands=()
    commands+=("add")
    commands+=("del")
    q_type="community"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_routepolicy_add_state()
{
    last_command="gobgp_policy_routepolicy_add_stat"
    commands=()
    q_type="routepolicy ${routepolicy}"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--a-community=")
    flags+=("--a-route=")
    flags+=("--c-aslen=")
    flags+=("--c-aspath=")
    flags+=("--c-community=")
    flags+=("--c-neighbor=")
    flags+=("--c-option=")
    flags+=("--c-prefix=")
    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_routepolicy_add()
{
    last_command="gobgp_policy_routepolicy_add"
    commands=()
    q_type="routepolicy"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--a-community=")
    flags+=("--a-route=")
    flags+=("--c-aslen=")
    flags+=("--c-aspath=")
    flags+=("--c-community=")
    flags+=("--c-neighbor=")
    flags+=("--c-option=")
    flags+=("--c-prefix=")
    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_routepolicy_del_all()
{
    last_command="gobgp_policy_routepolicy_del_all"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_routepolicy_del()
{
    last_command="gobgp_policy_routepolicy_del"
    commands=()
    commands+=("all")
    q_type="routepolicy"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy_routepolicy()
{
    last_command="gobgp_policy_routepolicy"
    commands=()
    commands+=("add")
    commands+=("del")
    q_type="routepolicy"
    __gobgp_q_policy

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_policy()
{
    last_command="gobgp_policy"
    commands=()
    commands+=("prefix")
    commands+=("neighbor")
    commands+=("aspath")
    commands+=("community")
    commands+=("routepolicy")

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

    must_have_one_flag=()
    must_have_one_noun=()
}

_gobgp_help()
{
    last_command="gobgp_help"
    commands=()

    flags=()
    two_word_flags=()
    flags_with_completion=()
    flags_completion=()

    flags+=("--help")
    flags+=("-h")

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
    flags+=("--help")
    flags+=("-h")
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
    _init_completion -s || return
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

    neighbor_searched="False"
    policy_searched="False"
    want_state="False"
    routepolicy=""


    __handle_word
}

complete -F __start_gobgp gobgp
# ex: ts=4 sw=4 et filetype=sh
