/*
 * Copyright (c) 2015 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/* jshint strict:true, globalstrict:true */
/* global Components, do_subtest */
/* exported run_test */

"use strict";


Components.utils.import("resource://dkim_verifier/SPF.jsm");

do_subtest("resource://dkim_verifier_tests/SPF-test-IP.js");
do_subtest("resource://dkim_verifier_tests/SPF-test-parse.js");

function run_test() {
}
