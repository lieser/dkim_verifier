/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */

import SignRules from "../../modules/dkim/signRules.mjs.js";
import { copy } from "../../modules/utils.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import sinon from "../helpers/sinonUtils.mjs.js";

describe("Sign rules [unittest]", function () {
	before(async function () {
		if (!hasWebExtensions) {
			// eslint-disable-next-line no-invalid-this
			this.skip();
		}
		await prefs.init();
	});

	beforeEach(async function () {
		await prefs.clear();
		await SignRules.clearRules();
	});

	const dkimNone = {
		version: "1.1",
		result: "none",
		warnings: []
	};
	const dkimSuccessTest = {
		version: "1.1",
		result: "SUCCESS",
		sdid: "test.com",
		auid: "@test.com",
		selector: "selector",
		/** @type {import("../../modules/dkim/verifier.mjs.js").dkimSigWarningV2[]} */
		warnings: []
	};
	const dkimSuccessPayPal = {
		version: "1.1",
		result: "SUCCESS",
		sdid: "paypal.com",
		auid: "@paypal.com",
		selector: "selector",
		warnings: []
	};

	describe("Default rules", function () {
		it("Not signed, and doesn't need to be signed", async function () {
			const res = await SignRules.check(dkimNone, "bar@foo.com");
			expect(res.result).is.equal("none");
		});
		it("Not signed, but should be signed", async function () {
			const res = await SignRules.check(dkimNone, "bar@paypal.com");
			expect(res.result).is.equal("PERMFAIL");
		});
		it("Signed by wrong signer", async function () {
			const res = await SignRules.check(dkimSuccessTest, "bar@paypal.com");
			expect(res.result).is.equal("PERMFAIL");
		});
		it("Signed by correct signer", async function () {
			const res = await SignRules.check(dkimSuccessPayPal, "bar@paypal.com");
			expect(res.result).is.equal("SUCCESS");
		});
		it("Not signed, default rules disabled", async function () {
			await prefs.setValue("policy.signRules.checkDefaultRules", false);
			const res = await SignRules.check(dkimNone, "bar@paypal.com");
			expect(res.result).is.equal("none");
		});
	});

	describe("User rules", function () {
		it("add must be signed rule", async function () {
			let res = await SignRules.check(dkimNone, "bar@foo.com");
			expect(res.result).is.equal("none");

			await SignRules.addRule("foo.com", null, "*", "foo.com", SignRules.TYPE.ALL);

			res = await SignRules.check(dkimNone, "bar@foo.com");
			expect(res.result).is.equal("PERMFAIL");
		});
		it("add must be signed rule for list", async function () {
			let res = await SignRules.check(dkimNone, "bar@example.com", "list@foo.com");
			expect(res.result).is.equal("none");

			await SignRules.addRule(null, "list@foo.com", "*", "foo.com", SignRules.TYPE.ALL);

			res = await SignRules.check(dkimNone, "bar@foo.com", "list@foo.com");
			expect(res.result).is.equal("PERMFAIL");
		});
		it("match address using glob", async function () {
			await SignRules.addRule("foo.com", null, "*@a.foo.com", "foo.com", SignRules.TYPE.ALL);

			let res = await SignRules.check(dkimNone, "bar@foo.com");
			expect(res.result).is.equal("none");

			res = await SignRules.check(dkimNone, "@a.foo.com");
			expect(res.result).is.equal("PERMFAIL");

			res = await SignRules.check(dkimNone, "bar@A.foo.com");
			expect(res.result).is.equal("PERMFAIL");

			res = await SignRules.check(dkimNone, "bar@b.foo.com");
			expect(res.result).is.equal("none");

			res = await SignRules.check(dkimNone, "bar@a.foo.comX");
			expect(res.result).is.equal("none");
		});
		it("Add user exception", async function () {
			let res = await SignRules.check(dkimNone, "bar@paypal.com");
			expect(res.result).is.equal("PERMFAIL");

			await SignRules.addException("bar@paypal.com");

			res = await SignRules.check(dkimNone, "bar@paypal.com");
			expect(res.result).is.equal("none");

			res = await SignRules.check(dkimNone, "foo@paypal.com");
			expect(res.result).is.equal("PERMFAIL");
		});
		it("Auto add rule", async function () {
			await prefs.setValue("policy.signRules.autoAddRule.enable", true);

			let res = await SignRules.check(dkimSuccessTest, "foo@test.com");
			expect(res.result).is.equal("SUCCESS");

			res = await SignRules.check(dkimNone, "foo@test.com");
			expect(res.result).is.equal("PERMFAIL");
		});
		it("Rule matching List-Id", async function () {
			await SignRules.addRule(null, "list.example.com", "*", "", SignRules.TYPE.NEUTRAL);

			const res = await SignRules.check(dkimNone, "bar@paypal.com", "list.example.com");
			expect(res.result).is.equal("none");
		});
		it("Suppress address not in SDID rule", async function () {
			const dkimRes = copy(dkimSuccessTest);
			dkimRes.warnings.push({ name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID" });

			await SignRules.addRule("example.com", null, "*", "", SignRules.TYPE.ALL);

			let res = await SignRules.check(dkimRes, "bar@example.com");
			expect(res.result).is.equal("SUCCESS");
			expect(res.warnings).to.be.an('array').
				that.deep.includes({ name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID" });

			await SignRules.addRule("example.com", null, "*", "test.com", SignRules.TYPE.NEUTRAL);

			res = await SignRules.check(dkimRes, "bar@example.com");
			expect(res.result).is.equal("SUCCESS");
			expect(res.warnings).to.be.an('array').
				that.not.deep.includes({ name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID" });
		});
		it("rules should survive clearing of preferences", async function () {
			await SignRules.addRule("foo.com", null, "*", "foo.com", SignRules.TYPE.ALL);
			const rules = (await browser.storage.local.get("signRulesUser")).signRulesUser;
			await SignRules.clearRules();
			await browser.storage.local.set({ signRulesUser: rules });

			prefs.clear();

			const res = await SignRules.check(dkimNone, "bar@foo.com");
			expect(res.result).is.equal("PERMFAIL");
		});
	});
	describe("outgoing mail", function () {
		it("outgoing mail must not be signed", async function () {
			let res = await SignRules.check(dkimNone, "bar@paypal.com", "", () => Promise.resolve(false));
			expect(res.result).is.equal("PERMFAIL");
			res = await SignRules.check(dkimNone, "bar@paypal.com", "", () => Promise.resolve(true));
			expect(res.result).is.equal("none");
		});
		it("check that callback is not called unnecessarily", async function () {
			const callback = sinon.fake.rejects("should not be called");

			let res = await SignRules.check(dkimNone, "bar@test.com", "", callback);
			expect(res.result).is.equal("none");
			expect(callback.notCalled).to.be.true;

			res = await SignRules.check(dkimSuccessPayPal, "bar@paypal.com", "", callback);
			expect(res.result).is.equal("SUCCESS");
			expect(callback.notCalled).to.be.true;
		});
	});
});
