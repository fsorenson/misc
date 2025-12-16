TARGETS = nfs_ssc.html

ifeq "$(shell which asciidoctor-pdf >/dev/null 2>&1 && echo $$?)" "0"
	# have asciidoctor-pdf

	ifeq "$(shell gem list -i pygments.rb)" "true"
		TARGETS += nfs_ssc.pdf
	else
		$(warning "cannot generate pdf - install pygments.rb: gem install pygments.rb")
	endif
else
	$(warning "cannot generate pdf - install asciidoctor-pdf")
endif

all: $(TARGETS)

nfs_ssc.html: nfs_ssc.adoc
	asciidoc -a data-uri -a icons -a toc -a max-width=55em nfs_ssc.adoc

nfs_ssc.pdf: nfs_ssc.adoc
	asciidoctor-pdf nfs_ssc.adoc

clean:
	rm -f nfs_ssc.html nfs_ssc.pdf
