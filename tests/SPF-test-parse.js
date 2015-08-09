/*
 * Copyright (c) 2015 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/* jshint strict:true, globalstrict:true, moz:true */
/* global Assert, SPF */
/* exported run_test */

"use strict";


function rfcSimpleExamples_01() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 +all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_01");
}

function rfcSimpleExamples_02() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "a",
				domain_spec: undefined,
				ip4_cidr_length: 32,
				ip6_cidr_length: 128,
			}, {
				type: "mechanism",
				qualifier: "-",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 a -all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_02");
}

function rfcSimpleExamples_03() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "a",
				domain_spec: "example.org",
				ip4_cidr_length: 32,
				ip6_cidr_length: 128,
			}, {
				type: "mechanism",
				qualifier: "-",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 a:example.org -all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_03");
}

function rfcSimpleExamples_04() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "mx",
				domain_spec: undefined,
				ip4_cidr_length: 32,
				ip6_cidr_length: 128,
			}, {
				type: "mechanism",
				qualifier: "-",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 mx -all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_04");
}

function rfcSimpleExamples_05() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "mx",
				domain_spec: "example.org",
				ip4_cidr_length: 32,
				ip6_cidr_length: 128,
			}, {
				type: "mechanism",
				qualifier: "-",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 mx:example.org -all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_05");
}

function rfcSimpleExamples_06() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "mx",
				domain_spec: undefined,
				ip4_cidr_length: 32,
				ip6_cidr_length: 128,
			}, {
				type: "mechanism",
				qualifier: "+",
				mechanism: "mx",
				domain_spec: "example.org",
				ip4_cidr_length: 32,
				ip6_cidr_length: 128,
			}, {
				type: "mechanism",
				qualifier: "-",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 mx mx:example.org -all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_06");
}

function rfcSimpleExamples_07() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "mx",
				domain_spec: undefined,
				ip4_cidr_length: 30,
				ip6_cidr_length: 128,
			}, {
				type: "mechanism",
				qualifier: "+",
				mechanism: "mx",
				domain_spec: "example.org",
				ip4_cidr_length: 30,
				ip6_cidr_length: 128,
			}, {
				type: "mechanism",
				qualifier: "-",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 mx/30 mx:example.org/30 -all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_07");
}

function rfcSimpleExamples_08() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "ptr",
				domain_spec: undefined,
			}, {
				type: "mechanism",
				qualifier: "-",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 ptr -all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_08");
}

function rfcSimpleExamples_09() {
	let res_exp = {
		version: "spf1",
		mechanism: [{
				type: "mechanism",
				qualifier: "+",
				mechanism: "ip4",
				ip4: "192.0.2.128",
				ip4_cidr_length: 28,
			}, {
				type: "mechanism",
				qualifier: "-",
				mechanism: "all",
			}
		],
		modifier: [],
	};
	let res = SPF._parseRecord("v=spf1 ip4:192.0.2.128/28 -all");
	Assert.deepEqual(res, res_exp, "rfcSimpleExamples_09");
}

function run_test() {
  rfcSimpleExamples_01();
  rfcSimpleExamples_02();
  rfcSimpleExamples_03();
  rfcSimpleExamples_04();
  rfcSimpleExamples_05();
  rfcSimpleExamples_06();
  rfcSimpleExamples_07();
  rfcSimpleExamples_08();
  rfcSimpleExamples_09();
}
