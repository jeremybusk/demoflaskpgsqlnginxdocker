#!/bin/bash
# Simple tests for while http service is running

test_portal_index_contains () {

    for i in {1..5}; do
        res="$(curl https://demoportal.uvoo.io)"
        if [[ $(echo "${res}" | grep -i Login) ]]; then
            exit 0
        fi
        sleep 5
    done
    echo "Response: ${res}"
    echo "E: Display issue. Couldn't find "login" in login page repeated times."
    exit 1 
}

test_api_ethereum() {
    res=$(curl -H "demoapp1_token: Hp3LEdOloVdjJQONMGjNcppPw0Do5joW" -H "Content-Type: application/json" -X POST --data '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}' https://api.uvoo.io/ethereum/)

    if [[ ! "${res}" == *"result"* ]]; then
        echo "Response: ${res}"
        echo "E: Failed to properly connect and get result from ethereum api."
        exit 1
    fi
} 

    
test_portal_index_contains
test_api_ethereum
