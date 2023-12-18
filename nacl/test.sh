#!/bin/bash

set -ex

priv=$(./nacl genkey)
pub=$(echo "$priv" | ./nacl pubkey)
overhead=48
test $(./nacl seal <(echo "$pub") </dev/null | wc --bytes) -eq "$overhead"
test $(echo AAAA | ./nacl seal <(echo "$pub") | ./nacl unseal <(echo "$priv")) = AAAA
test $(echo AAAA | base64 | ./nacl -b seal <(echo "$pub") | ./nacl -b unseal <(echo "$priv") | base64 -d ) = AAAA
