#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

$CC $CFLAGS $SANITIZER_FLAGS -c $SRC/fuzz_vuln.c -I.
$CC $CFLAGS $SANITIZER_FLAGS -c $SRC/integration-test/vuln.c -I.
$CC $CFLAGS $SANITIZER_FLAGS $LIB_FUZZING_ENGINE fuzz_vuln.o vuln.o -o $OUT/fuzz_vuln

cp $SRC/*.options $OUT/
