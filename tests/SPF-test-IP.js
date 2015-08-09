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


function ipv6_parse() {
	Assert.deepEqual(
		(new SPF._IP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))._buffer,
		[32,1,13,184,133,163,0,0,0,0,138,46,3,112,115,52],
		"ipv6_parse"
	);
	Assert.deepEqual(
		(new SPF._IP("2001:db8:85a3:0:0:8a2e:370:7334"))._buffer,
		[32,1,13,184,133,163,0,0,0,0,138,46,3,112,115,52],
		"ipv6_parse leading zeroes"

	);
	Assert.deepEqual(
		(new SPF._IP("2001:db8:85a3::8a2e:370:7334"))._buffer,
		[32,1,13,184,133,163,0,0,0,0,138,46,3,112,115,52],
		"ipv6_parse groups of zeroes"

	);
}

function run_test() {
  ipv6_parse();
}
