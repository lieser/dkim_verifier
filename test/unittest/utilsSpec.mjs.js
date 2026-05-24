/**
 * Copyright (c) 2020-2021;2023;2025-2026 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import {
	addrIsInDomain,
	addrIsInDomain2,
	dateToString,
	domainIsInDomain,
	encodeBase64Url,
	getDomainFromAddr,
	promiseWithTimeout,
	stringEndsWith,
	stringEqual,
	toBinaryString,
} from "../../modules/utils.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";

describe("utils [unittest]", function () {
	describe("addrIsInDomain", function () {
		it("addr is in domain", function () {
			expect(
				addrIsInDomain("foo@bar.com", "bar.com")
			).to.be.true;
		});

		it("addr is in domain (different casing)", function () {
			expect(
				addrIsInDomain("foo@bar.com", "bAr.Com")
			).to.be.true;
		});

		it("addr is in a sub-domain", function () {
			expect(
				addrIsInDomain("foo@sub.bar.com", "bar.com")
			).to.be.true;
		});

		it("addr is only in base-domain", function () {
			expect(
				addrIsInDomain("foo@bar.com", "sub.bar.com")
			).to.be.false;
		});

		it("addr is not in domain", function () {
			expect(
				addrIsInDomain("foo@bar.com", "foo.com")
			).to.be.false;
		});

		it("addr is not an e-mail", function () {
			expect(
				addrIsInDomain("bar.com", "bar.com")
			).to.be.false;
		});
	});

	describe("addrIsInDomain2", function () {
		it("addr is in domain", function () {
			expect(
				addrIsInDomain2("foo@bar.com", "bar.com")
			).to.be.true;
		});

		it("addr is in domain (different casing)", function () {
			expect(
				addrIsInDomain2("foo@bar.com", "bAr.Com")
			).to.be.true;
		});

		it("addr is in a sub-domain", function () {
			expect(
				addrIsInDomain2("foo@sub.bar.com", "bar.com")
			).to.be.true;
		});

		it("addr is in base-domain", function () {
			expect(
				addrIsInDomain2("foo@bar.com", "sub.bar.com")
			).to.be.true;
		});

		it("addr is not in domain", function () {
			expect(
				addrIsInDomain2("foo@bar.com", "foo.com")
			).to.be.false;
		});

		it("addr is not an e-mail", function () {
			expect(
				addrIsInDomain2("bar.com", "bar.com")
			).to.be.false;
		});
	});

	describe("dateToString", function () {
		it("Double digit month an day", function () {
			const date = new Date(2021, 11, 21);
			expect(dateToString(date)).to.be.equal("2021-12-21");
		});

		it("Single digit month an day", function () {
			const date = new Date(2021, 8, 6);
			expect(dateToString(date)).to.be.equal("2021-09-06");
		});
	});

	describe("domainIsInDomain", function () {
		it("domain is same", function () {
			expect(
				domainIsInDomain("bar.com", "bar.com")
			).to.be.true;
		});

		it("domain is same (different casing)", function () {
			expect(
				domainIsInDomain("bAr.com", "bar.cOm")
			).to.be.true;
		});

		it("domain is in a sub-domain", function () {
			expect(
				domainIsInDomain("sub.bar.com", "bar.com")
			).to.be.true;
		});

		it("addr is in base-domain", function () {
			expect(
				domainIsInDomain("bar.com", "sub.bar.com")
			).to.be.false;
		});
	});

	describe("encodeBase64Url", function () {
		it("With padding", function () {
			// @ts-expect-error
			const bytes = Uint8Array.fromHex("666f6f62"); // "foob"
			const encoded = encodeBase64Url(bytes, false);
			expect(encoded).to.be.equal("Zm9vYg==");
		});

		it("Without padding", function () {
			// @ts-expect-error
			const bytes = Uint8Array.fromHex("666f6f62"); // "foob"
			const encoded = encodeBase64Url(bytes, true);
			expect(encoded).to.be.equal("Zm9vYg");
		});

		it("Encoding alphabet of base64url", function () {
			{
				// Example from https://datatracker.ietf.org/doc/html/rfc8484#section-4.1.1
				// @ts-expect-error
				const bytes = Uint8Array.fromHex("00000100000100000000000001613e36326368617261637465726c6162656c2d6d616b65732d62617365363475726c2d64697374696e63742d66726f6d2d7374616e646172642d626173653634076578616d706c6503636f6d0000010001");
				const encoded = encodeBase64Url(bytes, true);
				expect(encoded).to.be.equal("AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1zdGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ");
			}
			{
				// Example from https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array/toBase64#encoding_data_with_url-safe_alphabet
				const bytes = new Uint8Array([46, 139, 222, 255, 42, 46]);
				const encoded = encodeBase64Url(bytes, true);
				expect(encoded).to.be.equal("Love_you");
			}
		});
	});

	describe("getDomainFromAddr", function () {
		it("base-domain", function () {
			expect(
				getDomainFromAddr("foo@bar.com")
			).to.be.equal("bar.com");
		});

		it("sub-domain", function () {
			expect(
				getDomainFromAddr("foo@sub.bar.com")
			).to.be.equal("sub.bar.com");
		});
	});

	describe("promiseWithTimeout", function () {
		it("no timeout", async function () {
			const res = await promiseWithTimeout(100, Promise.resolve(true));
			expect(res).to.be.true;

			await promiseWithTimeout(100, new Promise(resolve => { setTimeout(resolve, 50); }));
		});

		it("timeout", async function () {
			let timedOut = true;
			try {
				await promiseWithTimeout(50, new Promise(resolve => { setTimeout(resolve, 100); }));
				timedOut = false;
			} catch {
				// expected
			}
			expect(timedOut).to.be.true;
		});
	});

	describe("stringEndsWith", function () {
		it("string at end", function () {
			expect(
				stringEndsWith("foobar", "bar")
			).to.be.true;
		});

		it("string at end (different casing)", function () {
			expect(
				stringEndsWith("foobAr", "baR")
			).to.be.true;
		});

		it("string at front", function () {
			expect(
				stringEndsWith("foobar", "foo")
			).to.be.false;
		});

		it("string in middle", function () {
			expect(
				stringEndsWith("foomuhbar", "muh")
			).to.be.false;
		});

		it("string not included", function () {
			expect(
				stringEndsWith("foobar", "muh")
			).to.be.false;
		});
	});

	describe("stringEqual", function () {
		it("string equal", function () {
			expect(
				stringEqual("bar", "bar")
			).to.be.true;
		});

		it("string equal (different casing)", function () {
			expect(
				stringEqual("BAr", "BaR")
			).to.be.true;
		});

		it("string at front", function () {
			expect(
				stringEqual("foobar", "foo")
			).to.be.false;
		});

		it("string in middle", function () {
			expect(
				stringEqual("foomuhbar", "muh")
			).to.be.false;
		});

		it("string at end", function () {
			expect(
				stringEqual("foobar", "bar")
			).to.be.false;
		});

		it("string not included", function () {
			expect(
				stringEqual("foobar", "muh")
			).to.be.false;
		});
	});

	describe("toBinaryString", function () {
		it("ASCII only", function () {
			expect(
				toBinaryString("bar\r\nfoo")
			).to.be.equal("bar\r\nfoo");
		});

		it("Non ascii", function () {
			expect(
				toBinaryString("\u2014") // —
			).to.be.equal("\u00E2\u0080\u0094");

			expect(
				toBinaryString("🌃") // U+1F303
			).to.be.equal("\u00F0\u009F\u008C\u0083");

			expect(
				toBinaryString("a🌃 b— c👍")
			).to.be.equal("a\u00F0\u009F\u008C\u0083 b\u00E2\u0080\u0094 c\u00F0\u009F\u0091\u008D");
		});
	});
});
