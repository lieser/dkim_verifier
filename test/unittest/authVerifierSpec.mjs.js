/**
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */
/* eslint-disable camelcase */

import AuthVerifier from "../../modules/authVerifier.mjs.js";
import DMARC from "../../modules/dkim/dmarc.mjs.js";
import KeyStore from "../../modules/dkim/keyStore.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import Verifier from "../../modules/dkim/verifier.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import { queryDnsTxt } from "../helpers/dnsStub.mjs.js";
import { readTestFile } from "../helpers/testUtils.mjs.js";
import sinon from "../helpers/sinonUtils.mjs.js";

/**
 * @returns {browser.messages.MessageHeader}
 */
function createFakeMessageHeader() {
	return {
		author: "from@example.com",
		bccList: [],
		ccList: [],
		date: new Date(),
		external: false,
		flagged: false,
		folder: { accountId: "fakeAccount", path: "", type: "inbox" },
		headerMessageId: "",
		headersOnly: false,
		id: 42,
		junk: false,
		junkScore: 0,
		read: true,
		new: false,
		recipients: ["to@example.com"],
		size: 42,
		subject: "A fake message",
		tags: [],
	};
}

/**
 * @param {Map<string, string[]>} headers
 * @param {string} name
 * @returns {string[]}
 */
function extractHeaderValue(headers, name) {
	const completeHeaders = headers.get(name);
	if (completeHeaders === undefined) {
		return [];
	}
	return completeHeaders.map(header =>
		header.substr(name.length + ": ".length).slice(0, -"\r\n".length));
}

/**
 * @param {string} file - path to file relative to test data directory
 * @returns {Promise<browser.messages.MessageHeader>}
 */
async function createMessageHeader(file) {
	const fakeMessageHeader = createFakeMessageHeader();
	const msgPlain = await readTestFile(file);
	const msgParsed = MsgParser.parseMsg(msgPlain);
	fakeMessageHeader.author = extractHeaderValue(msgParsed.headers, "from")[0] ?? "";
	fakeMessageHeader.recipients = extractHeaderValue(msgParsed.headers, "to");
	fakeMessageHeader.subject = extractHeaderValue(msgParsed.headers, "subject")[0] ?? "";
	// @ts-expect-error
	browser.messages = {};
	browser.messages.getRaw = sinon.fake.resolves(msgPlain);
	return fakeMessageHeader;
}

describe("AuthVerifier [unittest]", function () {
	const dkimVerifier = new Verifier(new KeyStore(queryDnsTxt));
	const authVerifier = new AuthVerifier(dkimVerifier);

	before(async function () {
		if (!hasWebExtensions) {
			// eslint-disable-next-line no-invalid-this
			this.skip();
		}
		await prefs.init();
	});

	beforeEach(async function () {
		await prefs.clear();
	});

	describe("saving of results", function () {
		/** @type {import("../../modules/dkim/verifier.mjs.js").dkimResultV1|import("../../modules/authVerifier.mjs.js").AuthResultV2|import("../../modules/authVerifier.mjs.js").SavedAuthResultV3} */
		let storedData;

		beforeEach(async function () {
			await prefs.setValue("saveResult", true);

			browser.storageMessage = {
				get: sinon.stub().callsFake(() => JSON.stringify(storedData)),
				set: sinon.fake.throws("no fake for browser.storageMessage.set"),
			};
		});

		it("loading dkimResultV1", async function () {
			storedData = {
				version: "1.1",
				result: "none",
			};
			let res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0]?.res_num).to.be.equal(40);
			expect(res.dkim[0]?.result).to.be.equal("none");
			expect(res.dkim[0]?.result_str).to.be.equal("No Signature");

			storedData = {
				version: "1.1",
				result: "SUCCESS",
				SDID: "test.com",
				selector: "selector",
				warnings: ["DKIM_SIGWARNING_EXPIRED"]
			};
			res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0]?.res_num).to.be.equal(10);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by test.com)");
			expect(res.dkim[0]?.warnings_str).to.be.deep.equal(["Signature is expired"]);
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
			expect(res.dkim[0]?.res_num).to.be.equal(40);
			expect(res.dkim[0]?.result).to.be.equal("none");

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
			expect(res.dkim[0]?.res_num).to.be.equal(10);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by bad.com)");
			expect(res.dkim[0]?.sdid).to.be.equal("bad.com");
			expect(res.dkim[0]?.warnings_str).to.be.deep.equal(["Wrong signer (should be test.com)"]);

			expect(res.spf && res.spf[0]?.result).to.be.equal("pass");
			expect(res.dmarc && res.dmarc[0]?.result).to.be.equal("fail");
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
			expect(res.dkim[0]?.res_num).to.be.equal(40);
			expect(res.dkim[0]?.result).to.be.equal("none");

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
			expect(res.dkim[0]?.res_num).to.be.equal(30);
			expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
			expect(res.dkim[0]?.result_str).to.be.equal("Invalid (Signature has an unsupported version)");

			expect(res.dmarc && res.dmarc[0]?.result).to.be.equal("pass");
		});
	});

	describe("sign rules", function () {
		it("unsigned PayPal message", async function () {
			const fakePayPalMessage = await createMessageHeader("fakePayPal.eml");
			let res = await authVerifier.verify(fakePayPalMessage);
			expect(res.dkim[0]?.result).to.be.equal("none");

			await prefs.setValue("policy.signRules.enable", true);

			res = await authVerifier.verify(fakePayPalMessage);
			expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
			expect(res.dkim[0]?.result_str).to.be.equal("Invalid (No Signature, should be signed by paypal.com)");
		});

		it("outgoing mail", async function () {
			await prefs.setValue("policy.signRules.enable", true);
			const fakePayPalMessage = await createMessageHeader("fakePayPal.eml");

			let res = await authVerifier.verify(fakePayPalMessage);
			expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
			expect(res.dkim[0]?.result_str).to.be.equal("Invalid (No Signature, should be signed by paypal.com)");

			if (!fakePayPalMessage.folder) {
				throw new Error("Expect faked message to be in a fake folder");
			}
			fakePayPalMessage.folder.type = "sent";

			res = await authVerifier.verify(fakePayPalMessage);
			expect(res.dkim[0]?.result).to.be.equal("none");
		});

		it("DMARC", async function () {
			const fakePayPalMessage = await createMessageHeader("fakePayPal.eml");
			const dmarc = new DMARC(queryDnsTxt);
			const verifier = new AuthVerifier(dkimVerifier, dmarc);
			await prefs.setValue("policy.signRules.enable", true);
			await prefs.setValue("policy.signRules.checkDefaultRules", false);
			let res = await verifier.verify(fakePayPalMessage);
			expect(res.dkim[0]?.result).to.be.equal("none");

			await prefs.setValue("policy.DMARC.shouldBeSigned.enable", true);

			res = await verifier.verify(fakePayPalMessage);
			expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
			expect(res.dkim[0]?.result_str).to.be.equal("Invalid (No Signature, should be signed by paypal.com)");
		});
	});

	describe("ARH header", function () {
		it("spf and dkim result", async function () {
			const message = await createMessageHeader("rfc6376-A.2-arh-valid.eml");
			let res = await authVerifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.spf).to.be.equal(undefined);

			await prefs.setValue("dkim.enable", false);

			res = await authVerifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("none");

			await prefs.setValue("arh.read", true);

			res = await authVerifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect((res.spf ?? [])[0]?.result).to.be.equal("pass");
		});
		it("relaxed parsing", async function () {
			const message = await createMessageHeader("rfc6376-A.2-arh-valid_relaxed.eml");
			await prefs.setValue("arh.read", true);

			let res = await authVerifier.verify(message);
			expect(res.spf?.length).to.be.equal(0);

			await prefs.setValue("arh.relaxedParsing", true);

			res = await authVerifier.verify(message);
			expect((res.spf ?? [])[0]?.result).to.be.equal("pass");
		});
		describe("Converting of ARH result to DKIM result", function () {
			beforeEach(async function () {
				await prefs.setValue("dkim.enable", false);
				await prefs.setValue("arh.read", true);
			});

			it("DKIM pass with only SDID", async function () {
				const message = await createMessageHeader("rfc6376-A.2-arh-valid.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");
			});
			it("DKIM pass with only AUID", async function () {
				const message = await createMessageHeader("rfc6376-A.2-arh-valid-auid.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by football.example.com)");
				expect(res.dkim[0]?.sdid).to.be.equal("football.example.com");
				expect(res.dkim[0]?.auid).to.be.equal("joe@football.example.com");
			});
			it("DKIM pass with both SDID and AUID", async function () {
				const message = await createMessageHeader("rfc6376-A.2-arh-valid-sdid_and_auid.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("joe@football.example.com");
			});
			it("DKIM fail with reason", async function () {
				const message = await createMessageHeader("rfc6376-A.2-arh-failed.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid (bad signature)");
			});
			it("DKIM fail without reason", async function () {
				const message = await createMessageHeader("rfc6376-A.2-arh-failed-no_reason.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid");
			});
			it("DKIM results should be sorted", async function () {
				const message = await createMessageHeader("arh-multiple_dkim_results.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[1]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[1]?.sdid).to.be.equal("example.org");
				expect(res.dkim[2]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[2]?.sdid).to.be.equal("unrelated.org");
				expect(res.dkim[3]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[3]?.result_str).to.be.equal("Invalid (test failure)");
				expect(res.dkim[4]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[4]?.result_str).to.be.equal("Invalid");
				expect(res.dkim[5]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[5]?.result_str).to.be.equal("Invalid");
				expect(res.dkim[6]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[6]?.result_str).to.be.equal("Invalid (test failure signed by unrelated)");
			});
			it("With secure signature algorithm", async function () {
				const message = await createMessageHeader("rfc6376-A.2-arh-valid-a_tag.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.warnings_str).to.be.deep.equal([]);
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");
			});
			it("With insecure signature algorithm", async function () {
				const message = await createMessageHeader("rfc6376-A.2-arh-valid-a_tag_sha1.eml");

				let res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.warnings_str).to.be.deep.equal(["Insecure signature algorithm"]);
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");

				prefs.setValue("error.algorithm.sign.rsa-sha1.treatAs", 0);
				res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid (Insecure signature algorithm)");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");

				prefs.setValue("error.algorithm.sign.rsa-sha1.treatAs", 2);
				res = await authVerifier.verify(message);
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.warnings_str).to.be.deep.equal([]);
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");
			});
		});
	});

	describe("invalid messages", function () {
		it("ill-formed from shows proper error message", async function () {
			const message = await createMessageHeader("ill_formed-from.eml");
			const res = await authVerifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
			expect(res.dkim[0]?.result_str).to.be.equal("From address is ill-formed");
		});

		it("ill-formed list-id is ignored", async function () {
			const message = await createMessageHeader("rfc6376-A.2-ill_formed-list_id.eml");
			const res = await authVerifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
		});
	});
});
