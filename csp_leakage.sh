#!/usr/bin/env bash
#
# trace_ciphertexts.sh
#
# Usage:
#   ./trace_ciphertexts.sh <PID>
#
# This script uses bpftrace to trace calls to openat() by the specified PID,
# looking for filenames containing “ciphertexts”. It counts how many times such
# files are opened within each 5-second interval and prints the count when no
# matching open calls have occurred for 5 seconds.
#

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <PID>"
    exit 1
fi

PID="$1"

# Run bpftrace with an embedded program
bpftrace -e "
BEGIN {
    @cnt = 0;
    @last = nsecs;
}

tracepoint:syscalls:sys_enter_openat
/ pid == ${PID} && strcontains(str(args->filename + 73), \"ciphertexts\") / {
    printf(\"Opened: %s\n\", str(args->filename + 73));
    @cnt += 1;
    @last = nsecs;
}

interval:s:5 {
    if (nsecs - @last > 5000000000) {
        printf(\"Count in last window: %u\n\", @cnt);
        printf(\"\\n\");
        @cnt = 0;
        @last = nsecs;
    }
}
"
