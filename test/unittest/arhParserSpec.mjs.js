/**
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import ArhParser from "../../modules/arhParser.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { toBinaryString } from "../helpers/testUtils.mjs.js";

describe("ARH Parser [unittest]", function () {
	describe("RFC 7601 Appendix B Example", function () {
		it("B.2.  Nearly Trivial Case; Service Provided, but No Authentication Done", function () {
			const res = ArhParser.parse(
				"Authentication-Results: example.org 1; none\r\n");
			expect(res.authserv_id).to.be.equal("example.org");
			expect(res.authres_version).to.be.equal(1);
			expect(res.resinfo.length).to.be.equal(0);
		});
		it("B.3.  Service Provided, Authentication Done", function () {
			const res = ArhParser.parse(
				"Authentication-Results: example.com;\r\n" +
				"          spf=pass smtp.mailfrom=example.net\r\n");
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.authres_version).to.be.equal(1);
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("spf");
			expect(res.resinfo[0]?.method_version).to.be.equal(1);
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.smtp.mailfrom).to.be.equal("example.net");
		});
		it("B.4.  Service Provided, Several Authentications Done, Single MTA", function () {
			let res = ArhParser.parse(
				"Authentication-Results: example.com;\r\n" +
				"          auth=pass (cram-md5) smtp.auth=sender@example.net;\r\n" +
				"          spf=pass smtp.mailfrom=example.net\r\n");
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(2);
			expect(res.resinfo[0]?.method).to.be.equal("auth");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.smtp.auth).to.be.equal("sender@example.net");
			expect(res.resinfo[1]?.method).to.be.equal("spf");
			expect(res.resinfo[1]?.result).to.be.equal("pass");
			expect(res.resinfo[1]?.propertys.smtp.mailfrom).to.be.equal("example.net");
			// From [RFC 7601]
			res = ArhParser.parse(
				"Authentication-Results: example.com;\r\n" +
				"          sender-id=pass header.from=example.net\r\n");
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("sender-id");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.header.from).to.be.equal("example.net");
			// From [RFC 8601]
			res = ArhParser.parse(
				"Authentication-Results: example.com; iprev=pass\r\n" +
				"          policy.iprev=192.0.2.200\r\n");
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("iprev");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.policy.iprev).to.be.equal("192.0.2.200");
		});
		it("B.5.  Service Provided, Several Authentications Done, Different MTAs", function () {
			// From [RFC 7601]
			let res = ArhParser.parse(
				"Authentication-Results: example.com;\r\n" +
				"          sender-id=fail header.from=example.com;\r\n" +
				"          dkim=pass (good signature) header.d=example.com\r\n");
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(2);
			expect(res.resinfo[0]?.method).to.be.equal("sender-id");
			expect(res.resinfo[0]?.result).to.be.equal("fail");
			expect(res.resinfo[0]?.propertys.header.from).to.be.equal("example.com");
			expect(res.resinfo[1]?.method).to.be.equal("dkim");
			expect(res.resinfo[1]?.result).to.be.equal("pass");
			expect(res.resinfo[1]?.propertys.header.d).to.be.equal("example.com");
			// From [RFC 8601]
			res = ArhParser.parse(
				"Authentication-Results: example.com;\r\n" +
				"          dkim=pass (good signature) header.d=example.com\r\n");
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.header.d).to.be.equal("example.com");
			res = ArhParser.parse(
				"Authentication-Results: example.com;\r\n" +
				"          auth=pass (cram-md5) smtp.auth=sender@example.com;\r\n" +
				"          spf=fail smtp.mailfrom=example.com\r\n");
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(2);
			expect(res.resinfo[0]?.method).to.be.equal("auth");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.smtp.auth).to.be.equal("sender@example.com");
			expect(res.resinfo[1]?.method).to.be.equal("spf");
			expect(res.resinfo[1]?.result).to.be.equal("fail");
			expect(res.resinfo[1]?.propertys.smtp.mailfrom).to.be.equal("example.com");
		});
		it("B.6.  Service Provided, Multi-tiered Authentication Done", function () {
			let res = ArhParser.parse(
				"Authentication-Results: example.com;\r\n" +
				'      dkim=pass reason="good signature"\r\n' +
				"        header.i=@mail-router.example.net;\r\n" +
				'      dkim=fail reason="bad signature"\r\n' +
				"        header.i=@newyork.example.com\r\n");
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(2);
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.reason).to.be.equal("good signature");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("@mail-router.example.net");
			expect(res.resinfo[1]?.method).to.be.equal("dkim");
			expect(res.resinfo[1]?.result).to.be.equal("fail");
			expect(res.resinfo[1]?.reason).to.be.equal("bad signature");
			expect(res.resinfo[1]?.propertys.header.i).to.be.equal("@newyork.example.com");
			res = ArhParser.parse(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass (good signature) header.i=@newyork.example.com\r\n");
			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("@newyork.example.com");
		});
		it("B.7.  Comment-Heavy Example", function () {
			const res = ArhParser.parse(
				"Authentication-Results: foo.example.net (foobar) 1 (baz);\r\n" +
				"    dkim (Because I like it) / 1 (One yay) = (wait for it) fail\r\n" +
				"      policy (A dot can go here) . (like that) expired\r\n" +
				"      (this surprised me) = (as I wasn't expecting it) 1362471462\r\n");
			expect(res.authserv_id).to.be.equal("foo.example.net");
			expect(res.authres_version).to.be.equal(1);
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.method_version).to.be.equal(1);
			expect(res.resinfo[0]?.result).to.be.equal("fail");
			expect(res.resinfo[0]?.propertys.policy.expired).to.be.equal("1362471462");
		});
	});
	describe("Valid examples", function () {
		it("authserv-id in quotes", function () {
			const res = ArhParser.parse(
				'Authentication-Results: "example.org"; none\r\n');
			expect(res.authserv_id).to.be.equal("example.org");
			expect(res.authres_version).to.be.equal(1);
			expect(res.resinfo.length).to.be.equal(0);
		});
	});
	describe("Relaxed parsing", function () {
		it("Trailing ;", function () {
			const arh =
				"Authentication-Results: example.com;\r\n" +
				"          spf=pass smtp.mailfrom=example.net;\r\n";

			expect(() => ArhParser.parse(arh)).to.throw();

			const res = ArhParser.parse(arh, true);
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("spf");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
		});
		it("Property with / not in quotes ", function () {
			const arh =
				"Authentication-Results: example.com;\r\n" +
				"          dkim=pass header.b=gfT/i2HB\r\n";

			expect(() => ArhParser.parse(arh)).to.throw();

			const res = ArhParser.parse(arh, true);
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.header.b).to.be.equal("gfT/i2HB");
		});
	});
	describe("DKIM results", function () {
		it("AUID with local part", function () {
			const res = ArhParser.parse(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass header.i=dkim+foo-bar@example.github.com\r\n");

			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("dkim+foo-bar@example.github.com");
		});
		it("quoted SDID and AUID", function () {
			const res = ArhParser.parse(
				"Authentication-Results: example.net;\r\n" +
				'      dkim=pass header.d="github.com" header.i="dkim+foo-bar@example.github.com"\r\n');

			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.header.d).to.be.equal("github.com");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("dkim+foo-bar@example.github.com");
		});
		it("a-tag", function () {
			const res = ArhParser.parse(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass header.a=rsa-sha256\r\n");

			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo.length).to.be.equal(1);
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.result).to.be.equal("pass");
			expect(res.resinfo[0]?.propertys.header.a).to.be.equal("rsa-sha256");
		});
	});
	describe("Internationalized Email", function () {
		it("Disabled by default", function () {
			expect(() => ArhParser.parse(toBinaryString(
				"Authentication-Results: éxamplé.org; none\r\n"
			))).to.throw();
			expect(() => ArhParser.parse(toBinaryString(
				"Authentication-Results: Bloß.de; none\r\n"
			))).to.throw();
			expect(() => ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass header.i=Bloß.de\r\n"
			))).to.throw();
		});
		it("Wrongly called with normal string", function () {
			// i.e. test that token does not match non ASCII characters
			expect(() => ArhParser.parse(
				"Authentication-Results: éxamplé.org; none\r\n",
				false, true)
			).to.throw();
			expect(() => ArhParser.parse(
				"Authentication-Results: с-балалайкой.рф; none\r\n",
				false, true)
			).to.throw();
		});
		it("U-label in authserv-id", function () {
			let res = ArhParser.parse(toBinaryString(
				'Authentication-Results: "éxamplé.org"; none\r\n'
			), false, true);
			expect(res.authserv_id).to.be.equal("éxamplé.org");

			res = ArhParser.parse(toBinaryString(
				'Authentication-Results: "с-балалайкой.рф"; none\r\n'
			), false, true);
			expect(res.authserv_id).to.be.equal("с-балалайкой.рф");

			res = ArhParser.parse(toBinaryString(
				'Authentication-Results: "日本語.jp"; none\r\n'
			), false, true);
			expect(res.authserv_id).to.be.equal("日本語.jp");

			res = ArhParser.parse(toBinaryString(
				'Authentication-Results: "Bloß.de"; none\r\n'
			), false, true);
			expect(res.authserv_id).to.be.equal("Bloß.de");
		});
		it("U-label in authserv-id must be in quotes", function () {
			expect(() => ArhParser.parse(toBinaryString(
				"Authentication-Results: éxamplé.org; none\r\n"
			), false, true)).to.throw();

			expect(() => ArhParser.parse(toBinaryString(
				"Authentication-Results: с-балалайкой.рф; none\r\n"
			), false, true)).to.throw();
		});
		it("A-label in authserv-id", function () {
			// öbb.at
			let res = ArhParser.parse(
				"Authentication-Results: xn-bb-eka.at; none\r\n");
			expect(res.authserv_id).to.be.equal("xn-bb-eka.at");

			// 日本語.jp
			res = ArhParser.parse(
				"Authentication-Results: xn--wgv71a119e.jp; none\r\n");
			expect(res.authserv_id).to.be.equal("xn--wgv71a119e.jp");
		});
		it("non-ASCII in pvalue", function () {
			let res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass header.i=Pelé@example.com\r\n"
			), false, true);
			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("Pelé@example.com");

			res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net;\r\n" +
				'      dkim=pass header.i="Pelé@example.com"\r\n'
			), false, true);
			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("Pelé@example.com");

			res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass header.i=二ノ宮@example.com\r\n"
			), false, true);
			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("二ノ宮@example.com");

			res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass header.i=二ノ宮@xn--wgv71a119e.jp\r\n"
			), false, true);
			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("二ノ宮@xn--wgv71a119e.jp");

			res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass header.i=二ノ宮@黒川.日本\r\n"
			), false, true);
			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("二ノ宮@黒川.日本");

			res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net;\r\n" +
				'      dkim=pass header.i="二ノ宮@黒川.日本"\r\n'
			), false, true);
			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("二ノ宮@黒川.日本");

			res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net;\r\n" +
				"      dkim=pass header.i=Bloß.de\r\n"
			), false, true);
			expect(res.authserv_id).to.be.equal("example.net");
			expect(res.resinfo[0]?.propertys.header.i).to.be.equal("Bloß.de");
		});
		it("non-ASCII in reasonspec", function () {
			const res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.com;\r\n" +
				'      dkim=fail reason="Tést reason"\r\n'
			), false, true);
			expect(res.authserv_id).to.be.equal("example.com");
			expect(res.resinfo[0]?.method).to.be.equal("dkim");
			expect(res.resinfo[0]?.result).to.be.equal("fail");
			expect(res.resinfo[0]?.reason).to.be.equal("Tést reason");

		});
		it("non-ASCII in CFWS", function () {
			const res = ArhParser.parse(toBinaryString(
				"Authentication-Results: example.net (éxamplé); none\r\n"
			), false, true);
			expect(res.authserv_id).to.be.equal("example.net");
		});
	});
});
