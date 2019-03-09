TESTS ?= $(shell find test -type f -name '*-test.js')

include node_modules/make-node/main.mk


# Perform self-tests.
check: test
