/**
 * Copyright (c) 2026 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import expect from "../helpers/chaiUtils.mjs.js";
import getBaseDomainFromAddr from "../../modules/publicSuffixList.mjs";

describe("Public Suffix List", function () {
	it("ICANN domain - domain only", function () {
		expect(getBaseDomainFromAddr("example.com")).is.equal("example.com");
		expect(getBaseDomainFromAddr("foo.example.com")).is.equal("example.com");
		expect(getBaseDomainFromAddr("bar.foo.example.com")).is.equal("example.com");

		expect(getBaseDomainFromAddr("example.co.uk")).is.equal("example.co.uk");
		expect(getBaseDomainFromAddr("foo.example.co.uk")).is.equal("example.co.uk");
		expect(getBaseDomainFromAddr("bar.foo.example.co.uk")).is.equal("example.co.uk");

		expect(getBaseDomainFromAddr("foo.example.com.cn")).is.equal("example.com.cn");

		expect(getBaseDomainFromAddr("foo.example.公司.cn")).is.equal("example.公司.cn");
	});

	it("ICANN domain - mail address", function () {
		expect(getBaseDomainFromAddr("mail@example.com")).is.equal("example.com");
		expect(getBaseDomainFromAddr("mail@foo.example.com")).is.equal("example.com");
		expect(getBaseDomainFromAddr("mail@bar.foo.example.com")).is.equal("example.com");

		expect(getBaseDomainFromAddr("mail@example.co.uk")).is.equal("example.co.uk");
		expect(getBaseDomainFromAddr("mail@foo.example.co.uk")).is.equal("example.co.uk");
		expect(getBaseDomainFromAddr("mail@bar.foo.example.co.uk")).is.equal("example.co.uk");

		expect(getBaseDomainFromAddr("mail@foo.example.com.cn")).is.equal("example.com.cn");

		expect(getBaseDomainFromAddr("mail@foo.example.公司.cn")).is.equal("example.公司.cn");

		expect(getBaseDomainFromAddr("foo@test.com")).is.equal("test.com");
	});

	it("PRIVATE domain", function () {
		expect(getBaseDomainFromAddr("spark-public.s3.amazonaws.com")).is.equal("spark-public.s3.amazonaws.com");
		expect(getBaseDomainFromAddr("foo.spark-public.s3.amazonaws.com")).is.equal("spark-public.s3.amazonaws.com");

		// Emails may be send from private domains that are on the public suffix list.
		expect(getBaseDomainFromAddr("s3.amazonaws.com")).is.equal("s3.amazonaws.com");
	});

	it("PRIVATE domain - mail address", function () {
		expect(getBaseDomainFromAddr("mail@s3.amazonaws.com")).is.equal("s3.amazonaws.com");
		expect(getBaseDomainFromAddr("mail@spark-public.s3.amazonaws.com")).is.equal("spark-public.s3.amazonaws.com");
		expect(getBaseDomainFromAddr("mail@foo.spark-public.s3.amazonaws.com")).is.equal("spark-public.s3.amazonaws.com");

		// Emails may be send from private domains that are on the public suffix list.
		expect(getBaseDomainFromAddr("mail@s3.amazonaws.com")).is.equal("s3.amazonaws.com");
	});
});
