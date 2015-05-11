#!bash

__gobgp_q() {
    gobgp 2>/dev/null "$@"
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
    local targets=("local adj-in adj-out reset softreset softresetin softresetout shutdown enable disable")
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        case "$cur" in
            *)
                COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur") )
                ;;
        esac
        return
    fi
    return
}

__gobgp_neighbr_list() {
    local url=""
    local port=""
    if [ ! -z "$gobgp_ip" ]; then
        url="-u $gobgp_ip"
    fi
    if [ ! -z "$gobgp_port" ]; then
        port="-p $gobgp_port"
    fi
    local neighbor_list=( $(__gobgp_q $url $port --quiet neighbor) )
    local target="$(__search_target "${neighbor_list[*]}")"
    if [ -z "$target" ]; then
        case "$cur" in
            *)
                COMPREPLY=( $( compgen -W "${neighbor_list[*]}" -- "$cur") )
                ;;
        esac
        __ltrim_colon_completions "$cur"
        return 0
    fi
    return 1
}


_gobgp_global_rib(){
    local targets="add del"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        case "$cur" in
            *)
                COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur" ) )
                ;;
        esac
        return
    fi
}

_gobgp_global() {
    local targets="rib"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        case "$cur" in
            *)
                COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur" ) )
                ;;
        esac
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
_gobgp_policy_prefix_add(){
    return
}
_gobgp_policy_prefix_del(){
    local targets="all"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        case "$cur" in
            *)
                COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur" ) )
                ;;
        esac
        return
    fi
}

_gobgp_policy_prefix(){
    local targets="add del"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        case "$cur" in
            *)
                COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur" ) )
                ;;
        esac
        return
    fi
	_gobgp_policy_prefix_${target}
}

_gobgp_policy() {
    local targets="prefix"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
        case "$cur" in
            *)
                COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur" ) )
                ;;
        esac
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