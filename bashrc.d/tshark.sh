# tshark helper functions
expand_frames() {
	local ct=0
	if [[ $# -gt 0 ]] ; then
		while [[ -n $1 ]] ; do
			[[ $ct -gt 0 ]] && echo -n " || "
			echo -n "frame.number==$1" ; ct=$(($ct+1))
			shift
		done
	else
		read frames
		expand_frames $frames
	fi
}

tshark_cols() {
	while [[ -n $1 ]] ; do
		echo -n " -z proto,colinfo,$1,$1"
		shift
	done
}
tshark_fields() {
#	echo -n " -Tfields -E header=y"
	echo -n " -Tfields -E header=n"
	while [[ -n $1 ]] ; do
		echo -n " -e $1"
		shift
	done
}
tshark_any_of() {
	local ct=0
	local args

	[[ -z $1 ]] && return
	local field=$1 ; shift
	if [[ $# -gt 0 ]] ; then
		while [[ -n $1 ]] ; do
			[[ $ct -gt 0 ]] && echo -n " || "
			echo -n "$field==$1" ; ct=$(($ct+1))
			shift
		done
	else
		read args
		tshark_any_of $field $args
	fi
}
