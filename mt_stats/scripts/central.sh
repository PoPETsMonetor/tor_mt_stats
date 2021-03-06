#!/bin/bash

# mt_stats path
LOCAL_DIR="/home/thien-nam/Code/tor/mt_stats"

# Retrieve published information from the specified Tor node and delete the
# local copy. Files are first moved to a "temp" folder in order to ensure
# atomicity of the copy/removal process
#     $1 - node ip address
#     $2 - username
#     $3 - mt_stats/ path
function retrieve(){
    if ssh $2@$1 ls $3/published/* 1> /dev/null 2>&1; then
	ssh $2@$1 mv $3/published/* $3/temp/
	scp $2@$1:$3/temp/* ${LOCAL_DIR}/published/
	ssh $2@$1 rm $3/temp/*
    fi
}

# Retrieve published mt_stats info. One line per node
retrieve "168.7.116.9" "thien-nam" "/home/thien-nam/Desktop/mt_stats"
retrieve "168.7.116.9" "thien-nam" "/home/thien-nam/Desktop/mt_stats2"

# Aggregate collected published info into a shared file
python ${LOCAL_DIR}/scripts/aggregate.py

# Delete
if ls ${LOCAL_DIR}/published/* 1> /dev/null 2>&1; then
   rm ${LOCAL_DIR}/published/*
fi
