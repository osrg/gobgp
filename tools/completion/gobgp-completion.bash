#!bash

__gobgp_q() {
    gobgp 2>/dev/null "$@"
}

__gobgp_address() {
    url=""
    port=""
    if [ ! -z "$gobgp_ip" ]; then
        url="-u $gobgp_ip"
    fi
    if [ ! -z "$gobgp_port" ]; then
        port="-p $gobgp_port"
    fi
}

__compreply() {
    targets="$@"
    case "$cur" in
        *)
            COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur" ) )
            ;;
    esac
    return
}

__search_target() {
    local word target c=1

    while [ $c -lt $cword ]; do
        word="${words[c]}"
        for target in $1; do
            if [ "$target" = "$word" ]; then
                echo "$target"
                return
            fi
        done
        ((c++))
    done
}

__gobgp_table_list() {
    local targets="local adj-in adj-out reset softreset softresetin softresetout shutdown enable disable policy"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
    if [ "$target" = "policy" ]; then
	    _gobgp_neighbor_policy
	fi
    return
}

__gobgp_neighbr_list() {
    __gobgp_address
    local targets=( $(__gobgp_q $url $port --quiet neighbor) )
    local target="$(__search_target "${targets[*]}")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        __ltrim_colon_completions "$cur"
        return 0
    fi
    return 1
}

__gobgp_policy_list() {
    __gobgp_address
    local targets=( $(__gobgp_q $url $port --quiet policy "${policy_kind}") )
    local target="$(__search_target "${targets[*]}")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        __ltrim_colon_completions "$cur"
        return 0
    fi
    latest_word="$target"
    return 1
}

__gobgp_policy_statement_list() {
    __gobgp_address
    local targets=( $(__gobgp_q $url $port --quiet policy routepolicy "${policy}") )
    local target="$(__search_target "${targets[*]}")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        __ltrim_colon_completions "$cur"
        return 0
    fi
    return 1
}

_gobgp_global_rib(){
    local targets="add del"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
}

_gobgp_global() {
    local targets="rib"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
    _gobgp_global_${target}
}

_gobgp_neighbor() {
   __gobgp_neighbr_list
   if [ $? -ne 0 ] ; then
       __gobgp_table_list
   fi
}

_gobgp_neighbor_policy_op() {
    local targets="import export"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
}

_gobgp_neighbor_policy() {
   local targets="add del"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
    _gobgp_neighbor_policy_op
}

_gobgp_policy_routepolicy_op(){
    policy="${latest_word}"
    __gobgp_policy_statement_list
    if [ $? -ne 0 ] ; then
        targets="conditions actions"
        local target="$(__search_target "$targets")"
        if [ -z "$target" ]; then
            __compreply ${targets}
            return
        fi
        return
    fi
}

_gobgp_policy_routepolicy(){
    local targets="add del"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
    policy_kind="routepolicy"
    __gobgp_policy_list
    if [ $? -ne 0 ] ; then
	    _gobgp_policy_routepolicy_op
	fi
}

_gobgp_policy_neighbor(){
    local targets="add del"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
    if [ "$target" = "del" ]; then
        policy_kind="neighbor"
	    __gobgp_policy_list
	fi
}

_gobgp_policy_prefix(){
    local targets="add del"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
    if [ "$target" = "del" ]; then
        policy_kind="prefix"
	    __gobgp_policy_list
	fi
}

_gobgp_policy() {
    local targets="prefix neighbor routepolicy"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        __compreply ${targets}
        return
    fi
    _gobgp_policy_${target}
}

_gobgp_gobgp() {
    case "$prev" in
	-h)
	    return
	    ;;
	*)
	    ;;
	esac

	case "$cur" in
	    -*)
		COMPREPLY=( $( compgen -W "-h" -- "$cur" ) )
		;;
	    *)
		COMPREPLY=( $( compgen -W "${commands[*]} " -- "$cur" ) )
		;;
	esac
}

_gobgp() {
    local commands=(
        global
        neighbor
        policy
    )

    COMPREPLY=()
    local cur prev words cword
    _get_comp_words_by_ref -n : cur prev words cword

    local command='gobgp'
    local counter=1
    while [ $counter -lt $cword ]; do
	case "${words[$counter]}" in
            -u)
                (( counter++ ))
                gobgp_ip="${words[$counter]}"
                ;;
            -p)
                (( counter++ ))
                gobgp_port="${words[$counter]}"
                ;;
	    -*)
		;;
	    *)
		command="${words[$counter]}"
		cpos=$counter
		(( cpos++ ))
		break
		;;
	esac
	(( counter++ ))
    done
    local completions_func=_gobgp_${command}
    declare -F $completions_func > /dev/null && $completions_func

    return 0
}

complete -F _gobgp gobgp