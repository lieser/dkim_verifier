/**
 * Copyright (c) 2020 Philippe Lieser
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
	domainIsInDomain,
	getDomainFromAddr,
	stringEndsWith,
	stringEqual,
	toType
} from "../../modules/utils.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";

describe("utils [unittest]", () => {
	describe("addrIsInDomain", () => {
		it("addr is in domain", () => {
			expect(
				addrIsInDomain("foo@bar.com", "bar.com")
			).to.be.true;
		});
		it("addr is in domain (different casing)", () => {
			expect(
				addrIsInDomain("foo@bar.com", "bAr.Com")
			).to.be.true;
		});
		it("addr is in a sub-domain", () => {
			expect(
				addrIsInDomain("foo@sub.bar.com", "bar.com")
			).to.be.true;
		});

		it("addr is only in base-domain", () => {
			expect(
				addrIsInDomain("foo@bar.com", "sub.bar.com")
			).to.be.false;
		});
		it("addr is not in domain", () => {
			expect(
				addrIsInDomain("foo@bar.com", "foo.com")
			).to.be.false;
		});
		it("addr is not an e-mail", () => {
			expect(
				addrIsInDomain("bar.com", "bar.com")
			).to.be.false;
		});
	});

	describe("addrIsInDomain2", () => {
		it("addr is in domain", () => {
			expect(
				addrIsInDomain2("foo@bar.com", "bar.com")
			).to.be.true;
		});
		it("addr is in domain (different casing)", () => {
			expect(
				addrIsInDomain2("foo@bar.com", "bAr.Com")
			).to.be.true;
		});
		it("addr is in a sub-domain", () => {
			expect(
				addrIsInDomain2("foo@sub.bar.com", "bar.com")
			).to.be.true;
		});
		it("addr is in base-domain", () => {
			expect(
				addrIsInDomain2("foo@bar.com", "sub.bar.com")
			).to.be.true;
		});

		it("addr is not in domain", () => {
			expect(
				addrIsInDomain2("foo@bar.com", "foo.com")
			).to.be.false;
		});
		it("addr is not an e-mail", () => {
			expect(
				addrIsInDomain2("bar.com", "bar.com")
			).to.be.false;
		});
	});

	describe("domainIsInDomain", () => {
		it("domain is same", () => {
			expect(
				domainIsInDomain("bar.com", "bar.com")
			).to.be.true;
		});
		it("domain is same (different casing)", () => {
			expect(
				domainIsInDomain("bAr.com", "bar.cOm")
			).to.be.true;
		});
		it("domain is in a sub-domain", () => {
			expect(
				domainIsInDomain("sub.bar.com", "bar.com")
			).to.be.true;
		});

		it("addr is in base-domain", () => {
			expect(
				domainIsInDomain("bar.com", "sub.bar.com")
			).to.be.false;
		});
	});

	describe("getDomainFromAddr", () => {
		it("base-domain", () => {
			expect(
				getDomainFromAddr("foo@bar.com")
			).to.be.equal("bar.com");
		});
		it("sub-domain", () => {
			expect(
				getDomainFromAddr("foo@sub.bar.com")
			).to.be.equal("sub.bar.com");
		});
	});

	describe("stringEndsWith", () => {
		it("string at end", () => {
			expect(
				stringEndsWith("foobar", "bar")
			).to.be.true;
		});
		it("string at end (different casing)", () => {
			expect(
				stringEndsWith("foobAr", "baR")
			).to.be.true;
		});

		it("string at front", () => {
			expect(
				stringEndsWith("foobar", "foo")
			).to.be.false;
		});
		it("string in middle", () => {
			expect(
				stringEndsWith("foomuhbar", "muh")
			).to.be.false;
		});
		it("string not included", () => {
			expect(
				stringEndsWith("foobar", "muh")
			).to.be.false;
		});
	});

	describe("stringEqual", () => {
		it("string equal", () => {
			expect(
				stringEqual("bar", "bar")
			).to.be.true;
		});
		it("string equal (different casing)", () => {
			expect(
				stringEqual("BAr", "BaR")
			).to.be.true;
		});

		it("string at front", () => {
			expect(
				stringEqual("foobar", "foo")
			).to.be.false;
		});
		it("string in middle", () => {
			expect(
				stringEqual("foomuhbar", "muh")
			).to.be.false;
		});
		it("string at end", () => {
			expect(
				stringEqual("foobar", "bar")
			).to.be.false;
		});
		it("string not included", () => {
			expect(
				stringEqual("foobar", "muh")
			).to.be.false;
		});
	});

	describe("toType", () => {
		it("Number", () => {
			expect(
				toType(42)
			).to.be.equal("Number");
		});
		it("Boolean", () => {
			expect(
				toType(true)
			).to.be.equal("Boolean");
		});
		it("Object", () => {
			expect(
				toType({})
			).to.be.equal("Object");
		});
		it("Map", () => {
			expect(
				toType(new Map())
			).to.be.equal("Map");
		});
	});
});
