#!/bin/bash

GHIDRA_DIR="$HOME/Downloads/ghidra_10.1.5_PUBLIC"

$PROJECT_PATH = $1
$PROJECT_NAME = $2
$BINARY_NAME = $3

$GHIDRA_DIR/support/analyzeHeadless \
    $1 $2 \
    -process $3 \
    -noanalysis -readOnly \
    -scriptPath $PWD \
    -postScript DumpFunctionOffsets.java
