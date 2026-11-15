#!/bin/sh
# Host test of the Packetwall rule engine (gcc + ASan/UBSan). Usage: ./run.sh
set -e
cd "$(dirname "$0")"
ROOT=../../../../../..
OUT=$(mktemp -d)
sed "s|@LIST@|$PWD/list.txt|" rules.txt.in > "$OUT/rules.txt"
gcc -Wall -O1 -fsanitize=address,undefined -I stub -I "$ROOT/submodules/zdtun" -I ../../core \
    pw_rules_test.c ../../core/pw_rules.c -o "$OUT/t" -lpthread
"$OUT/t" "$OUT/rules.txt"
