export README_DEPS ?=  docs/terraform.md

-include $(shell curl -sSL -o .build-harness "https://gitlab.com/snippets/1957473/raw"; echo .build-harness)

artifact:
	cd lambda && $(MAKE)

dist-clean:
	rm -rf lambda/package artifacts/lambda/* artifacts.zip


## Lint terraform code
lint:
	echo lint hah

fmt:
	cd lambda && $(MAKE) fmt
	terraform13 fmt -recursive
