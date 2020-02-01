// @ts-check
/* eslint-disable no-magic-numbers */

import {
	addrIsInDomain,
	addrIsInDomain2,
	domainIsInDomain,
	getDomainFromAddr,
	stringEndsWith,
	stringEqual,
	toType
} from "../../modules/utils.mjs.js";

describe("utils unit test", () => {
	describe("addrIsInDomain", () => {
		it("addr is in domain", () => {
			expect(
				addrIsInDomain("foo@bar.com", "bar.com")
			).toBeTrue();
		});
		it("addr is in domain (different casing)", () => {
			expect(
				addrIsInDomain("foo@bar.com", "bAr.Com")
			).toBeTrue();
		});
		it("addr is in a sub-domain", () => {
			expect(
				addrIsInDomain("foo@sub.bar.com", "bar.com")
			).toBeTrue();
		});

		it("addr is only in base-domain", () => {
			expect(
				addrIsInDomain("foo@bar.com", "sub.bar.com")
			).toBeFalse();
		});
		it("addr is not in domain", () => {
			expect(
				addrIsInDomain("foo@bar.com", "foo.com")
			).toBeFalse();
		});
		it("addr is not an e-mail", () => {
			expect(
				addrIsInDomain("bar.com", "bar.com")
			).toBeFalse();
		});
	});

	describe("addrIsInDomain2", () => {
		it("addr is in domain", () => {
			expect(
				addrIsInDomain2("foo@bar.com", "bar.com")
			).toBeTrue();
		});
		it("addr is in domain (different casing)", () => {
			expect(
				addrIsInDomain2("foo@bar.com", "bAr.Com")
			).toBeTrue();
		});
		it("addr is in a sub-domain", () => {
			expect(
				addrIsInDomain2("foo@sub.bar.com", "bar.com")
			).toBeTrue();
		});
		it("addr is in base-domain", () => {
			expect(
				addrIsInDomain2("foo@bar.com", "sub.bar.com")
			).toBeTrue();
		});

		it("addr is not in domain", () => {
			expect(
				addrIsInDomain2("foo@bar.com", "foo.com")
			).toBeFalse();
		});
		it("addr is not an e-mail", () => {
			expect(
				addrIsInDomain2("bar.com", "bar.com")
			).toBeFalse();
		});
	});

	describe("domainIsInDomain", () => {
		it("domain is same", () => {
			expect(
				domainIsInDomain("bar.com", "bar.com")
			).toBeTrue();
		});
		it("domain is same (different casing)", () => {
			expect(
				domainIsInDomain("bAr.com", "bar.cOm")
			).toBeTrue();
		});
		it("domain is in a sub-domain", () => {
			expect(
				domainIsInDomain("sub.bar.com", "bar.com")
			).toBeTrue();
		});

		it("addr is in base-domain", () => {
			expect(
				domainIsInDomain("bar.com", "sub.bar.com")
			).toBeFalse();
		});
	});

	describe("getDomainFromAddr", () => {
		it("base-domain", () => {
			expect(
				getDomainFromAddr("foo@bar.com")
			).toBe("bar.com");
		});
		it("sub-domain", () => {
			expect(
				getDomainFromAddr("foo@sub.bar.com")
			).toBe("sub.bar.com");
		});
	});

	describe("stringEndsWith", () => {
		it("string at end", () => {
			expect(
				stringEndsWith("foobar", "bar")
			).toBeTrue();
		});
		it("string at end (different casing)", () => {
			expect(
				stringEndsWith("foobAr", "baR")
			).toBeTrue();
		});

		it("string at front", () => {
			expect(
				stringEndsWith("foobar", "foo")
			).toBeFalse();
		});
		it("string in middle", () => {
			expect(
				stringEndsWith("foomuhbar", "muh")
			).toBeFalse();
		});
		it("string not included", () => {
			expect(
				stringEndsWith("foobar", "muh")
			).toBeFalse();
		});
	});

	describe("stringEqual", () => {
		it("string equal", () => {
			expect(
				stringEqual("bar", "bar")
			).toBeTrue();
		});
		it("string equal (different casing)", () => {
			expect(
				stringEqual("BAr", "BaR")
			).toBeTrue();
		});

		it("string at front", () => {
			expect(
				stringEqual("foobar", "foo")
			).toBeFalse();
		});
		it("string in middle", () => {
			expect(
				stringEqual("foomuhbar", "muh")
			).toBeFalse();
		});
		it("string at end", () => {
			expect(
				stringEqual("foobar", "bar")
			).toBeFalse();
		});
		it("string not included", () => {
			expect(
				stringEqual("foobar", "muh")
			).toBeFalse();
		});
	});

	describe("toType", () => {
		it("Number", () => {
			expect(
				toType(42)
			).toBe("Number");
		});
		it("Boolean", () => {
			expect(
				toType(true)
			).toBe("Boolean");
		});
		it("Object", () => {
			expect(
				toType({})
			).toBe("Object");
		});
		it("Map", () => {
			expect(
				toType(new Map())
			).toBe("Map");
		});
	});
});
