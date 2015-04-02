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
    local table_list=("local adj-in adj-out")
    local table="$(__search_target "${table_list}")"
    if [ -z "$table" ]; then
	case "$cur" in
	    *)
		COMPREPLY=( $( compgen -W "${table_list}" -- "$cur") )
		;;
	esac
	return
    fi
    COMPREPLY=( $( compgen -W "ipv4 ipv6 evpn" -- "$cur") )
    return
}

__gobgp_neighbr_list() {
    local neighbor_list=( $(__gobgp_q --quiet show neighbors) )
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

_gobgp_show_neighbor() {
   __gobgp_neighbr_list
   if [ $? -ne 0 ] ; then
       __gobgp_table_list
   fi
}

_gobgp_show_neighbors() {
    case "$cur" in
	*)
	    ;;
    esac
    return
}

_gobgp_show_global() {
    local targets="ipv4 ipv6 evpn"
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

_gobgp_show() {
    local targets="neighbor neighbors global"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
	case "$cur" in
	    *)
		COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur" ) )
		;;
	esac
	return
    fi
    _gobgp_show_${target}
}

__gobgp_generic_reset() {
    local targets="neighbor"
    local target="$(__search_target "$targets")"
    if [ -z "$target" ]; then
	case "$cur" in
	    *)
		COMPREPLY=( $( compgen -W "${targets[*]}" -- "$cur" ) )
		;;
	esac
	return
    fi
    __gobgp_neighbr_list
}

_gobgp_reset() {
    __gobgp_generic_reset
}

_gobgp_softreset() {
    __gobgp_generic_reset
}

_gobgp_softresetin() {
    __gobgp_generic_reset
}

_gobgp_softresetout() {
    __gobgp_generic_reset
}

_gobgp_shutdown() {
    __gobgp_generic_reset
}

_gobgp_enable() {
    __gobgp_generic_reset
}

_gobgp_disable() {
    __gobgp_generic_reset
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
		COMPREPLY=( $( compgen -W "${commands[*]} help" -- "$cur" ) )
		;;
	esac
}

_gobgp() {
    local commands=(
	show
	reset
	softreset
	softresetin
	softresetout
	shutdown
	enable
	disable
    )

    COMPREPLY=()
    local cur prev words cword
    _get_comp_words_by_ref -n : cur prev words cword

    local command='gobgp'
    local counter=1
    while [ $counter -lt $cword ]; do
	case "${words[$counter]}" in
	    -h)
		(( counter++ ))
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
