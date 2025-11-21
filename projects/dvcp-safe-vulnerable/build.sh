#!/bin/bash -eu
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Build the fuzzer
$CC $CFLAGS $LIB_FUZZING_ENGINE \
    -I$SRC/dvcp \
    $SRC/dvcp_fuzz.c \
    -o $OUT/dvcp_fuzz

# Create initial corpus
mkdir -p $OUT/dvcp_fuzz_seed_corpus

# Create some seed inputs
echo -ne "IMG\x00\x01\x00\x00\x00\x01\x00\x00\x00AAAAAAAAAA" > $OUT/dvcp_fuzz_seed_corpus/seed1
echo -ne "IMG\x00\x10\x00\x00\x00\x10\x00\x00\x00BBBBBBBBBB" > $OUT/dvcp_fuzz_seed_corpus/seed2
echo -ne "IMG\x00\xff\xff\xff\x7f\x10\x00\x00\x00CCCCCCCCCC" > $OUT/dvcp_fuzz_seed_corpus/seed3
