#!/bin/bash

STACK=$1
FUNC=$2

if [ -z $FUNC ] ; then
    echo "Usage: $0 <stackname> <function>"
    echo "Where function can be 'inventory' or 'sqs' or 'cwl'"
    exit 1
fi

if [ $FUNC == "sqs" ] ; then
    cp detect-SQS.py index.py
    zip -r upload.zip index.py
    aws lambda update-function-code --function-name ${STACK}-detect --zip-file fileb://upload.zip
    rm index.py upload.zip
fi

if [ $FUNC == "inventory" ] ; then
    cp inventory.py index.py
    zip -r upload.zip index.py
    aws lambda update-function-code --function-name ${STACK}-inventory --zip-file fileb://upload.zip
    rm index.py upload.zip
fi

# if [ $FUNC == "kinesis" ] ; then
#     cp detect-kinesis.py index.py
#     zip -r upload.zip index.py
#     aws lambda update-function-code --function-name ${STACK}-detect --zip-file fileb://upload.zip
#     rm index.py upload.zip
# fi


if [ $FUNC == "cwl" ] ; then
    cp detect-cwl.py index.py
    zip -r upload.zip index.py
    aws lambda update-function-code --function-name ${STACK}-detect --zip-file fileb://upload.zip
    rm index.py upload.zip
fi