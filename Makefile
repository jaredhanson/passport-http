NODE = node
TEST = ./node_modules/.bin/vows
TESTS ?= test/*-test.js test/**/*-test.js

test:
	@NODE_ENV=test NODE_PATH=lib $(TEST) $(TEST_FLAGS) $(TESTS)

docs: docs/api.html

docs/api.html: lib/passport-http/*.js
	dox \
		--title Passport-HTTP \
		--desc "HTTP Basic and Digest authentication strategies for Passport" \
		$(shell find lib/passport-http/* -type f) > $@

docclean:
	rm -f docs/*.{1,html}

.PHONY: test docs docclean
