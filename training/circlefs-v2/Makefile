TARGETS = writing_circlefs.html circlefs

ifeq "$(shell which asciidoctor-pdf >/dev/null 2>&1 && echo $$?)" "0"
	# have asciidoctor-pdf

	ifeq "$(shell gem list -i pygments.rb)" "true"
		TARGETS += writing_circlefs.pdf
	else
		$(warning "cannot generate pdf - install pygments.rb: gem install pygments.rb")
	endif
else
	$(warning "cannot generate pdf - install asciidoctor-pdf")
endif

all: $(TARGETS)

writing_circlefs.html: writing_circlefs.adoc
	asciidoc -a data-uri -a icons -a toc -a max-width=55em writing_circlefs.adoc

writing_circlefs.pdf: writing_circlefs.adoc
	asciidoctor-pdf writing_circlefs.adoc

circlefs: circlefs.c circlefs.h
	gcc -Wall circlefs.c -o circlefs -g -lm -lfuse3

clean:
	rm -f circlefs writing_circlefs.html writing_circlefs.pdf
