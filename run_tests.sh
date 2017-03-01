#!/bin/sh

if [ -z $@ ]; then
	test=iottly_authentication.tests.unittests
else
	test="$@"
fi

coverage run -m tornado.testing $test
