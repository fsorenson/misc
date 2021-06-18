diffhex () {
	diff --side-by-side <(hexdump -C $1) <(hexdump -C $2)
}
