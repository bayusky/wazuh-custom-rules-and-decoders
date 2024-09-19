#!/bin/bash


read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.misp.file_path)
LOG_FILE="logs/active-responses.log"
QUARANTINE_PATH="/tmp/quarantined"
TIMESTAMP=$(date '+%Y%m%d%H%M%S')

mkdir -p ${QUARANTINE_PATH}

cp -f $FILENAME ${QUARANTINE_PATH}/${FILEBASE}_${TIMESTAMP}
chattr -R +i ${QUARANTINE_PATH}/${FILEBASE}_${TIMESTAMP}

rm -f $FILENAME
if [ $? -eq 0 ]; then
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $FILENAME moved to ${QUARANTINE_PATH}. Successfully quarantine malware" >> ${LOG_FILE}
else
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: Error quarantine malware on $FILENAME" >> ${LOG_FILE}
fi
exit 0;
