#!/bin/bash
set -euo pipefail

for i in $(seq 1 ${1:-20}); do 
        perl -pe 's/__TPL__/"{a,'$RANDOM'}"/' bad_args.tpl
done 

