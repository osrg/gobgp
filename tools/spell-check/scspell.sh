#!/usr/bin/env bash

SCRIPT_DIR=`dirname $0`
GOBGP=${SCRIPT_DIR}/../../

RESULT=0

# Keeping dictionary.txt sorted keeps the diff of a new word small and easy to
# review. scspell sorts the dictionary when it loads it, so this is a
# convention rather than something scspell needs. Only the NATURAL section
# exists today, hence skipping just the first line. Add a word to a new section
# and this needs to check each section on its own.
#
# ignore.txt is deliberately not checked. The loop below removes each of its
# words with sed, one after another, so a word that is a prefix of a later word
# would truncate it and stop it from matching. Sorting is exactly the order
# that puts the prefix first.
if ! tail -n +2 ${SCRIPT_DIR}/dictionary.txt | LC_ALL=C sort -c
then
    echo "${SCRIPT_DIR}/dictionary.txt is not sorted"
    RESULT=1
fi

FUNCS=(
Debug
Debugf
Debugln
Error
Errorf
Errorln
Fatal
Fatalf
Fatalln
Fprint
Fprintf
Fprintln
Info
Infof
Infoln
Panic
Panicf
Panicln
Print
Printf
Println
Sprint
Sprintf
Sprintln
Warn
Warnf
Warning
Warningf
Warningln
Warnln
)

CHECK_LOG=/tmp/gobgp/scspell.log
mkdir -p `dirname ${CHECK_LOG}`
rm -f ${CHECK_LOG}  # Clean up previous output

# Do find *.go files except under vendor directory
for FILE in `find ${GOBGP} -type d -name vendor -prune -o -type f -name *.go | sort`
do
    TMP_FILE=${FILE/${GOBGP}//tmp/gobgp/}
    mkdir -p `dirname ${TMP_FILE}`
    rm -f ${TMP_FILE}  # Clean up previous output

    for FUNC in ${FUNCS[@]}
    do
        # Do grep cases like:
        #   fmt.Print("...")
        # or
        #   fmt.Print(
        #       "...")
        grep ${FUNC}'("'      ${FILE} | grep -o '".*"' >> ${TMP_FILE}
        grep ${FUNC}'($' -A 1 ${FILE} | grep -o '".*"' >> ${TMP_FILE}
    done

    # If any case found
    if [ -s ${TMP_FILE} ]
    then
        # Apply exclude rules defined in ignore.txt
        for WORD in `grep -v -e '^\s*#' -e '^$' ${SCRIPT_DIR}/ignore.txt`
        do
            sed -i "s/${WORD}//g" ${TMP_FILE}
        done

        # Do scspell with dictionary.txt and reformat messages
        scspell \
            --use-builtin-base-dict \
            --override-dictionary ${SCRIPT_DIR}/dictionary.txt \
            --report-only \
            ${TMP_FILE} 2>&1 \
         | tee -a ${CHECK_LOG} \
         | sed "s/\/tmp\/gobgp\///" | cut -d ':' -f -1,3-
    fi

    #rm ${TMP_FILE}
done

# If any output of scspell exists
if [ -s ${CHECK_LOG} ]
then
    echo "---"
    echo "See ${CHECK_LOG} for more details."
    # Set return code as error
    RESULT=1
fi

#rm -f ${CHECK_LOG}
exit ${RESULT}

