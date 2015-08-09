/*
 * Copyright (c) 2015 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/* jshint strict:true, globalstrict:true, moz:true */
/* global Components, Promise, DNS */
/* exported initDNSTestStub */

"use strict";

Components.utils.import("resource://dkim_verifier/DNSWrapper.jsm");


function initDNSTestStub() {
  if (DNS._dnsTestStubInitialized) {
		return;
	}
	DNS._dnsTestStubInitialized = true;
	DNS._DNSTestData = DNSTestData;
	let resolve_orig = DNS.resolve;
	DNS.resolve = function (name, rrtype="A") {
		let hostData = DNS._DNSTestData[name];
		if (!hostData) {
			return resolve_orig(name, rrtype);
		}
		let res = {
			data: hostData[rrtype] || null,
			rcode: 0,
			secure: false,
			bogus: false,
		};
		return new Promise(function(resolve/*, reject*/) {resolve(res);});
	};
}

var DNSTestData = {
	"example.com": {
		A: [
			"192.0.2.10",
			"192.0.2.11",
		],
		MX: [
			{preference: 10, host: "mail-a"},
			{preference: 20, host: "mail-b"},
		],
	},
	"amy.example.com": {
		A: [
			"192.0.2.65",
		],
	},
	"bob.example.com": {
		A: [
			"192.0.2.66",
		],
	},
	"mail-a.example.com": {
		A: [
			"192.0.2.129",
		],
	},
	"mail-b.example.com": {
		A: [
			"192.0.2.130",
		],
	},

	"example.org": {
		MX: [
			{preference: 10, host: "mail-c"},
		],
	},
	"mail-c.xample.org": {
		A: [
			"192.0.2.140",
		],
	},
};