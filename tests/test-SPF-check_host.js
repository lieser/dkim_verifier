/*
 * Copyright (c) 2015 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/* jshint strict:true, globalstrict:true, moz:true */
/* global Assert, do_load_module, do_test_pending, do_test_finished, do_print */
/* global Components, SPF, Task, initDNSTestStub, DNSTestData */
/* exported run_test */

"use strict";

Components.utils.import("resource://gre/modules/Task.jsm");

do_load_module("resource://dkim_verifier_tests/DNSTestStub.js");


function rfcSimpleExamples_01() {
	DNSTestData["example.com"].TXT = ["v=spf1 +all"];
	let spf_ctx = new SPF._SPFContext();
	let res;

	res = yield spf_ctx.check_host(
		"192.0.2.10", "example.com", "test@example.com");
	Assert.deepEqual(res, "pass", "rfcSimpleExamples_01 01");

	res = yield spf_ctx.check_host(
		"192.2.2.10", "example.com", "test@example.com");
	Assert.deepEqual(res, "pass", "rfcSimpleExamples_01 02");
}

function rfcSimpleExamples_02() {
	DNSTestData["example.com"].TXT = ["v=spf1 a -all"];
	let spf_ctx = new SPF._SPFContext();
	let res;

	res = yield spf_ctx.check_host(
		"192.0.2.10", "example.com", "test@example.com");
	Assert.deepEqual(res, "pass", "rfcSimpleExamples_02 01");

	res = yield spf_ctx.check_host(
		"192.0.2.11", "example.com", "test@example.com");
	Assert.deepEqual(res, "pass", "rfcSimpleExamples_02 02");

	res = yield spf_ctx.check_host(
		"192.2.2.10", "example.com", "test@example.com");
	Assert.deepEqual(res, "fail", "rfcSimpleExamples_02 03");
}

function rfcSimpleExamples_03() {
	DNSTestData["example.com"].TXT = ["v=spf1 a:example.org -all"];
	let spf_ctx = new SPF._SPFContext();
	let res;

	res = yield spf_ctx.check_host(
		"192.0.2.10", "example.com", "test@example.com");
	Assert.deepEqual(res, "fail", "rfcSimpleExamples_03 01");

	res = yield spf_ctx.check_host(
		"192.0.2.140", "example.com", "test@example.com");
	Assert.deepEqual(res, "fail", "rfcSimpleExamples_03 02");

	res = yield spf_ctx.check_host(
		"192.2.2.10", "example.com", "test@example.com");
	Assert.deepEqual(res, "fail", "rfcSimpleExamples_03 03");
}

function rfcSimpleExamples_04() {
	DNSTestData["example.com"].TXT = ["v=spf1 mx -all"];
	let spf_ctx = new SPF._SPFContext();
	let res;
}

function rfcSimpleExamples_05() {
	DNSTestData["example.com"].TXT = ["v=spf1 mx:example.org -all"];
	let spf_ctx = new SPF._SPFContext();
	let res;
}

function rfcSimpleExamples_06() {
	DNSTestData["example.com"].TXT = ["v=spf1 mx mx:example.org -all"];
	let spf_ctx = new SPF._SPFContext();
	let res;
}

function rfcSimpleExamples_07() {
	DNSTestData["example.com"].TXT = ["v=spf1 mx/30 mx:example.org/30 -all"];
	let spf_ctx = new SPF._SPFContext();
	let res;
}

function rfcSimpleExamples_08() {
	DNSTestData["example.com"].TXT = ["v=spf1 ptr -all"];
	let spf_ctx = new SPF._SPFContext();
	let res;
}

function rfcSimpleExamples_09() {
	DNSTestData["example.com"].TXT = ["v=spf1 ip4:192.0.2.128/28 -all"];
	let spf_ctx = new SPF._SPFContext();
	let res;

	res = yield spf_ctx.check_host(
		"192.0.2.65", "example.com", "test@example.com");
	Assert.deepEqual(res, "fail", "rfcSimpleExamples_09 01");

	res = yield spf_ctx.check_host(
		"192.0.2.129", "example.com", "test@example.com");
	Assert.deepEqual(res, "pass", "rfcSimpleExamples_09 02");

	res = yield spf_ctx.check_host(
		"192.2.2.10", "example.com", "test@example.com");
	Assert.deepEqual(res, "fail", "rfcSimpleExamples_09 03");
}

function run_test() {
	initDNSTestStub();

	Task.spawn(function () {
		do_test_pending();

		yield rfcSimpleExamples_01();
		yield rfcSimpleExamples_02();
		yield rfcSimpleExamples_03();
		// yield rfcSimpleExamples_04();
		// yield rfcSimpleExamples_05();
		// yield rfcSimpleExamples_06();
		// yield rfcSimpleExamples_07();
		// yield rfcSimpleExamples_08();
		yield rfcSimpleExamples_09();
	}).then(function onFulfill() {
		do_test_finished();
	},  function onReject(exception) {
		do_print(exception.toSource());
		do_test_finished();
	});
}
