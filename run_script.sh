#!/bin/bash
PROJECT="iottly_authentication"

# If the script moves this must be changed!
ROOT="$(dirname $0)"

SCRIPTS_DIR=$ROOT

PYTHON="/usr/local/bin/python"

PYTHONPATH=$ROOT:$PYTHONPATH; export PYTHONPATH

script_name=$1
shift 1;
args=$@

$PYTHON -m $PROJECT.main
