TARGETS = nfs_delegations.html

ifeq "$(shell which asciidoctor-pdf >/dev/null 2>&1 && echo $$?)" "0"
	# have asciidoctor-pdf

	ifeq "$(shell gem list -i pygments.rb)" "true"
		TARGETS += nfs_delegations.pdf
	else
		$(warning "cannot generate pdf - install pygments.rb: gem install pygments.rb")
	endif
else
	$(warning "cannot generate pdf - install asciidoctor-pdf")
endif

all: $(TARGETS)

nfs_delegations.html: nfs_delegations.adoc
	asciidoc -a data-uri -a icons -a toc -a max-width=55em nfs_delegations.adoc

nfs_delegations.pdf: nfs_delegations.adoc
	asciidoctor-pdf nfs_delegations.adoc

clean:
	rm -f nfs_delegations.html nfs_delegations.pdf
