BEGIN{SUBSEP=":"}
{
	if ($1=="#define" && substr($2,0,11)=="FATTR4_WORD") {
		word=int(substr($2,12,1));
		bit=int($5);
		cap=substr($2,14);
		cap_words[word][bit] = cap;

#		printf("word %d, bit %d: %s\n", word, bit, cap)
	}
}
function ind_str(i) { return substr("                               ", 0, i*4) }
function dump_var_pp(v, ind) {
	if (isarray(v)) {
#		printf("%s{\n", ind_str(ind));
		printf("{\n");
		for (key in v) {
			printf("%s[%s] => ", ind_str(ind + 1), key);
			if (isarray(v[key]))
				dump_var_pp(v[key], ind + 1)
			else
				printf("%s", v[key])
			printf(",\n")
		};
		printf("%s}\n", ind_str(ind));
	} else {
		printf("%s\n", v);
	}
}
function dump_var(v) {
	dump_var_pp(v, 0)


}
END{
#	printf("normal:\n");
#	for (word in cap_words) printf("cap word %d\n", word)

#	printf("\n");
#	printf("tricky:\n");
#	asort(cap_words, words)
#	for (word in words) printf("cap word %d\n", word)


#	printf("\n");
#	printf("dump:\n");
#	dump_var(cap_words)


	for (word in cap_words) {
		printf("my %nfs4_cap_word%d = (\n", word)
		for (key in cap_words[word]) {
			printf("\t%d => \"%s\",\n", key, cap_words[word][key])
		}
		printf(");\n");
	}

#	printf("SYMTAB:\n");
#	dump_var(SYMTAB)
}



#awk '{if ($1=="#define" && substr($2,0,11)=="FATTR4_WORD"){ word=int(substr($2,12,1); bit=int($5); cap=substr($2,14); cap_words[word,bit] = cap}}
#' ../../include/linux/nfs4.h

