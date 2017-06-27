SECTIONS {
	test8 ALIGN(., 4096): {
		PROVIDE (__start_test8 = .) ;
		__start_test8_abs = ABSOLUTE(.);

		*("test8.vars") ;
/*
		. = ALIGN(., 32) ;
		offsets = .;
		. = ALIGN(., 32) ;
		var6 = .;
		. = ALIGN(., 4096) ;
		FILL (1000) ;
		*(".data") ;
		*(".bss") ;
*/
		test8_data_end = (. - 1);

		. = ALIGN(., 4096) ;
		test8_func_start = ALIGN(4096) ;
		*("test8.funcs") ;
		*(".text")
		*(*)
		FILL (0xAA) ;

		. = ALIGN(., 4095) - 1;

		PROVIDE (__stop_test8 = .) ;
		KEEP(*(test8))
		test8_size = (__stop_test8 - __start_test8) ;
	}
}
