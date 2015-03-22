#!bash

__gobgpcli_q() {
    gobgpcli 2>/dev/null "$@"
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

__gobgpcli_table_list() {
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

__gobgpcli_neighbr_list() {
    local neighbor_list=( $(__gobgpcli_q show --quiet neighbors) )
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

_gobgpcli_show_neighbor() {
   __gobgpcli_neighbr_list
   if [ $? -ne 0 ] ; then
       __gobgpcli_table_list
   fi
}

_gobgpcli_show_neighbors() {
    case "$cur" in
	*)
	    ;;
    esac
    return
}

_gobgpcli_show_global() {
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

_gobgpcli_show() {
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
    _gobgpcli_show_${target}
}

__gobgpcli_generic_reset() {
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
    __gobgpcli_neighbr_list
}

_gobgpcli_reset() {
    __gobgpcli_generic_reset
}

_gobgpcli_softresetin() {
    __gobgpcli_generic_reset
}

_gobgpcli_softresetout() {
    __gobgpcli_generic_reset
}

_gobgpcli_shutdown() {
    __gobgpcli_generic_reset
}

_gobgpcli_gobgpcli() {
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

_gobgpcli() {
    local commands=(
	show
	reset
	softresetin
	softresetout
	shutdown
    )

    COMPREPLY=()
    local cur prev words cword
    _get_comp_words_by_ref -n : cur prev words cword

    local command='gobgpcli'
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
    local completions_func=_gobgpcli_${command}
    declare -F $completions_func > /dev/null && $completions_func

    return 0
}

complete -F _gobgpcli gobgpcli
