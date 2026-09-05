#!/bin/bash

usage() {
	echo "Usage: ${0##*/} <input_file> [filter_regex]" >&2
	exit 1
}

[[ $# -lt 1 || $# -gt 2 ]] && usage
[[ ! -f "$1" ]] && { echo "Error: '$1' not found" >&2; exit 1; }

input="$1"
filter="${2:-.}"

awk -v filter="$filter" '
/kernel: =+$/ {
	if (in_report) {
		if (matched) {
			for (i = 0; i < n; i++)
				print lines[i]
			print
		}
		delete lines
		n = 0
		in_report = 0
		matched = 0
	}
	in_report = 1
	lines[n++] = $0
	next
}
in_report {
	lines[n++] = $0
	if (/kernel: BUG: KCSAN: data-race/ && $0 ~ filter)
		matched = 1
}
END {
	if (in_report && matched) {
		for (i = 0; i < n; i++)
			print lines[i]
	}
}
' "$input"
