#!/bin/bash

CLIENT_JAR="./test_client_13_jsse_key_export/test_client_13_jsse_key_export.jar"
AGENT_JAR="./test_client_13_jsse_key_export/extract-tls-secrets-4.0.0.jar"
SECRET_FILE="./key.log"

if [ -f ./key.log ]; then
    rm ./key.log
fi

echo "Using: https://github.com/neykov/extract-tls-secrets"

read -p "Press enter to proceed..."

# Start the client application with attached agent
java -javaagent:"$AGENT_JAR"="$SECRET_FILE" -jar "$CLIENT_JAR"                                                     

# Open ./key.log and print its content
if [ -f ./key.log ]; then
    cat ./key.log
else
    echo "Error: key.log not found."
fi

wait $CLIENT_PID
