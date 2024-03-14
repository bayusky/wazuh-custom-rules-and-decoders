#!/bin/bash

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`

read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.misp.file_path)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"
QUARANTINE_PATH="/tmp/quarantined"

# Quarantine file
/usr/bin/mv -f $FILENAME ${QUARANTINE_PATH}
FILEBASE=$(/usr/bin/basename $FILENAME)
/usr/bin/chattr -R +i ${QUARANTINE_PATH}/${FILEBASE}

rm -f $FILENAME
if [ $? -eq 0 ]; then
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $FILENAME moved to ${QUARANTINE_PATH}. Successfully quarantine threat" >> ${LOG_FILE}
else
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $FILENAME Error quarantine threat" >> ${LOG_FILE}
fi

exit 0;
