SECTIONS {
	test9 ALIGN(., 4096): {
		__test9_start = .;
		*("test9.vars") ;
/*
		. = ALIGN(., 32) ;
		offsets = .;
		. = ALIGN(., 32) ;
		var6 = .;
		. = ALIGN(., 4096) ;
		*(".data") ;
		*(".bss") ;
*/
		test9_data_end = (. - 1);

		. = ALIGN(., 4096) ;
		test9_func_start = ALIGN(4096) ;
		*("test9.funcs") ;

		. = ALIGN(., 4096) - 1;

		KEEP(*(test9));
		__test9_end = .;
	}
	misc ALIGN(., 4096): {
		*(*)
		*(".text");
	}
	test9_section_base = ADDR(test9);
	test9_section_size = SIZEOF(test9);
	set_func_addr = set_var9_func;
	set_func_offset = ADDR(set_func_addr) - ADDR(test9_section_base);
	get_func_addr = get_var9_func;
	print_func_addr = print_var9_func;
	test9_section_end = ADDR(test9) + SIZEOF(test9);
}
