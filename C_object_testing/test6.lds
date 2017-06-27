SECTIONS {
	test6 ALIGN(., 4096): {
		PROVIDE (__start_test6 = .) ;


		*("test6.vars") ;
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
		test6_data_end = (. - 1);

		. = ALIGN(., 4096) ;
		test6_func_start = ALIGN(4096) ;
		*("test6.funcs") ;
		*(".text")
		*(*)
		FILL (0xAA) ;

/*		. = ALIGN(., 4095); */
		. = ALIGN(., 4095) - 1;

		PROVIDE (__stop_test6 = .) ;
		test6_size = (__stop_test6 - __start_test6) ;
	}
/*	.debug_macro 0 : { *(.debug_macro); } */


/*	.debug_macro: { .debug_macro :*  */

/*	`.debug_macro' referenced in section `test6' of test6.o: defined in discarded section `.debug_macro[wm4.stdcpredef.h.19.bf2bf6c5fb087dfb5ef2d2297c2795de]' of test6.o */

}

/*
;		set_var6_func = .;
;		get_var6_func ;
;		print_var6_func = .;
*/
