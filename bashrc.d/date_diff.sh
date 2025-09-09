date_diff() { d1=$(date -d "$1" +%s.%N); d2=$(date -d "$2" +%s.%N); echo "$d2 - $d1" | bc ; }
