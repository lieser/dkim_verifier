/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../WebExtensions.d.ts" />
/* eslint-env webextensions */
/* eslint-disable camelcase */

import AuthVerifier from "../../modules/AuthVerifier.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import sinon from "../helpers/sinonUtils.mjs.js";

/**
 * @returns {browser.messageDisplay.MessageHeader}
 */
function createFakeMessageHeader() {
	return {
		author: "from@example.com",
		bccList: [],
		ccList: [],
		date: new Date(),
		flagged: false,
		folder: { accountId: "fakeAccount" },
		id: 42,
		junk: false,
		junkScore: 0,
		read: true,
		recipients: ["to@example.com"],
		subject: "A fake message",
		tags: [],
	};
}

describe("AuthVerifier [unittest]", function () {

	describe("saving of results", function () {
		const authVerifier = new AuthVerifier();
		/** type {VerifierModule.dkimResultV1|AuthResultV2|SavedAuthResultV3} */
		/** @type {import("../../modules/dkim/verifier.mjs.js").dkimResultV1|import("../../modules/AuthVerifier.mjs.js").AuthResultV2|import("../../modules/AuthVerifier.mjs.js").SavedAuthResultV3} */
		let storedData;

		before(async function () {
			if (!hasWebExtensions) {
				// eslint-disable-next-line no-invalid-this
				this.skip();
			}
			await prefs.init();
			await prefs.clear();
			prefs.setValue("saveResult", true);

			browser.storageMessage = {
				// get: sinon.fake.resolves(JSON.stringify(storedData)),
				get: sinon.stub().callsFake(() => JSON.stringify(storedData)),
				set: sinon.fake.throws(""),
			};
		});

		beforeEach(async function () {
			// await prefs.clear();
		});

		it("loading dkimResultV1", async function () {
			storedData = {
				version: "1.1",
				result: "none",
			};
			let res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0].res_num).to.be.equal(40);
			expect(res.dkim[0].result).to.be.equal("none");
			expect(res.dkim[0].result_str).to.be.equal("No Signature");

			storedData = {
				version: "1.1",
				result: "SUCCESS",
				SDID: "test.com",
				selector: "selector",
				warnings: ["DKIM_SIGWARNING_EXPIRED"]
			};
			res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0].res_num).to.be.equal(10);
			expect(res.dkim[0].result).to.be.equal("SUCCESS");
			expect(res.dkim[0].result_str).to.be.equal("Valid (Signed by test.com)");
			expect(res.dkim[0].warnings_str).to.be.deep.equal(["Signature is expired"]);
		});

		it("loading AuthResultV2", async function () {
			storedData = {
				version: "2.0",
				dkim: [{
					version: "2.0",
					result: "none",
				}],
			};
			let res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0].res_num).to.be.equal(40);
			expect(res.dkim[0].result).to.be.equal("none");

			storedData = {
				version: "2.0",
				dkim: [{
					version: "2.0",
					result: "SUCCESS",
					sdid: "bad.com",
					selector: "selector",
					warnings: [{ name: "DKIM_POLICYERROR_WRONG_SDID", params: ["test.com"] }]
				}],
				spf: [{
					method: "spf",
					method_version: 1,
					result: "pass",
					propertys: { smtp: {}, header: {}, body: {}, policy: {} },
				}],
				dmarc: [{
					method: "dmarc",
					method_version: 1,
					result: "fail",
					propertys: { smtp: {}, header: {}, body: {}, policy: {} },
				}],
			};
			res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0].res_num).to.be.equal(10);
			expect(res.dkim[0].result).to.be.equal("SUCCESS");
			expect(res.dkim[0].result_str).to.be.equal("Valid (Signed by bad.com)");
			expect(res.dkim[0].sdid).to.be.equal("bad.com");
			expect(res.dkim[0].warnings_str).to.be.deep.equal(["Wrong signer (should be test.com)"]);

			expect(res.spf && res.spf[0].result).to.be.equal("pass");
			expect(res.dmarc && res.dmarc[0].result).to.be.equal("fail");
		});

		it("loading SavedAuthResultV3", async function () {
			storedData = {
				version: "3.0",
				dkim: [{
					version: "1.1",
					result: "none",
				}],
			};
			let res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0].res_num).to.be.equal(40);
			expect(res.dkim[0].result).to.be.equal("none");

			storedData = {
				version: "3.0",
				dkim: [{
					version: "2.0",
					result: "PERMFAIL",
					errorType: "DKIM_SIGERROR_UNKNOWN_C_H",
				}],
				dmarc: [{
					method: "dmarc",
					method_version: 1,
					result: "pass",
					propertys: { smtp: {}, header: {}, body: {}, policy: {} },
				}],
			};
			res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0].res_num).to.be.equal(30);
			expect(res.dkim[0].result).to.be.equal("PERMFAIL");
			expect(res.dkim[0].result_str).to.be.equal("Invalid (Signature has an unsupported version)");

			expect(res.dmarc && res.dmarc[0].result).to.be.equal("pass");
		});
	});
});
