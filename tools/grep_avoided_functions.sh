#!/usr/bin/env bash

# List of functions which should not be used with remarkable reasons
FUNCS=(
# On a 32-bit platform, int type is not big enough to convert into uint32 type.
# strconv.Atoi() should be replaced by strconv.ParseUint() or
# strconv.ParseInt().
'strconv\.Atoi'
)

SCRIPT_DIR=`dirname $0`
cd "${SCRIPT_DIR}/.."

RESULT=0

PKG_BASE=github.com/osrg/gobgp/v3

for FUNC in ${FUNCS[@]}
do
    for GO_PKG in $(go list $PKG_BASE/... | grep -v '/vendor/')
    do
        grep ${FUNC} -r ${GO_PKG#$PKG_BASE/}
        if [ $? -ne 1 ]
        then
            RESULT=1
        fi
    done
done

exit $RESULT