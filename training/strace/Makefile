TARGETS = strace.html trace

ifeq "$(shell which asciidoctor-pdf >/dev/null 2>&1 && echo $$?)" "0"
	# have asciidoctor-pdf

	ifeq "$(shell gem list -i pygments.rb)" "true"
		TARGETS += strace.pdf
	else
		$(warning "cannot generate pdf - install pygments.rb: gem install pygments.rb")
	endif
else
	$(warning "cannot generate pdf - install asciidoctor-pdf")
endif

all: $(TARGETS)

strace.html: strace.adoc
	asciidoc -a data-uri -a icons -a toc -a max-width=55em strace.adoc

strace.pdf: strace.adoc
	asciidoctor-pdf strace.adoc

trace: trace.c
	gcc -Wall trace.c -o trace

clean:
	rm -f strace.html strace.pdf
