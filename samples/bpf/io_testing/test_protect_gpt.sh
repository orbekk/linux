#!/bin/bash
#WARNING: may overwrite GPT, use on scratch disk only
#Tests attempts to write to various parts of disk
#While program is attached, writes to GPT should be blocked while all other regions allowed

echo "Running tests for protect_gpt bpf program"

if [[ $# -ne 1 ]]; then
	echo "Please enter device as argument"
	exit 1
fi

TEST_DEV=$1
GPT_SIZE=34	#number sectors in GPT
SECTOR_SIZE=512	#bytes per sector

#change to folder containing programs, 
#protect_gpt needs to be run in same folder as protect_gpt_kern.o
#TODO: update based on dir structure when added to xfstests
cd ..

#Load program:
./protect_gpt $TEST_DEV protect_gpt${TEST_DEV//\//_} --attach 1> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed to load protect_gpt program"
	exit 1
fi

#Test: write to first GPT_SIZE blocks
#	should fail
dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE count=$GPT_SIZE oflag=direct &> /dev/null 

if [[ $? -eq 0 ]]; then
	echo "Failed test: program allowed writing to GPT"
	./protect_gpt $TEST_DEV protect_gpt${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi

#Test: write to last block of GPT and first block after GPT all in one IO request
#	should fail
dd if=/dev/zero of="$TEST_DEV" bs=$((2 * $SECTOR_SIZE)) seek=$((($GPT_SIZE-1) * $SECTOR_SIZE)) count=1 oflag=direct,seek_bytes &> /dev/null
if [[ $? -eq 0 ]]; then
	echo "Failed test: program allowed writing to last block of GPT"
	./protect_gpt $TEST_DEV protect_gpt${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi

#Test: write to block after first GPT_SIZE blocks
#	should pass
dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=$GPT_SIZE count=1 oflag=direct &> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed test: program blocked writing to non-GPT sector"
	./protect_gpt $TEST_DEV protect_gpt${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi

#Detach program
./protect_gpt $TEST_DEV protect_gpt${TEST_DEV//\//_} --detach 1> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed to detach protect_gpt program"
	exit 1
fi

#Test: write to first GPT_SIZE blocks
#	should pass
dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE count=$GPT_SIZE oflag=direct &> /dev/null 

if [[ $? -ne 0 ]]; then
	echo "Failed test: program blocked writing to GPT after detach"
	exit 1
fi

echo "All tests passed."
exit 0
