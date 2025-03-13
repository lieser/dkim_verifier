/**
 * Copyright (c) 2020-2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable camelcase */

import "../helpers/initWebExtensions.mjs.js";
import AuthVerifier from "../../modules/authVerifier.mjs.js";
import { DKIM_TempError } from "../../modules/error.mjs.js";
import DMARC from "../../modules/dkim/dmarc.mjs.js";
import DNS from "../../modules/dns.mjs.js";
import KeyStore from "../../modules/dkim/keyStore.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import SignRules from "../../modules/dkim/signRules.mjs.js";
import Verifier from "../../modules/dkim/verifier.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
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
	browser.messages.getRaw = sinon.fake.resolves(msgPlain);
	return fakeMessageHeader;
}

describe("AuthVerifier [unittest]", function () {
	const dkimVerifier = new Verifier(new KeyStore(queryDnsTxt));
	const authVerifier = new AuthVerifier(dkimVerifier);

	before(async function () {
		await prefs.init();
	});

	beforeEach(async function () {
		await prefs.clear();
	});

	describe("saving of results", function () {
		// eslint-disable-next-line mocha/no-setup-in-describe
		const storageMessageGet = sinon.fake.resolves("");
		// eslint-disable-next-line mocha/no-setup-in-describe
		const storageMessageSet = sinon.fake.resolves(undefined);

		before(async function () {
			await prefs.init();
			browser.storageMessage = {
				get: storageMessageGet,
				set: storageMessageSet,
			};
		});

		beforeEach(async function () {
			await prefs.setValue("saveResult", true);

			storageMessageGet.resetHistory();
			storageMessageSet.resetHistory();
		});

		it("Store SUCCESS result", async function () {
			const message = await createMessageHeader("rfc8463-A.3.eml");
			const res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(2);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[1]?.result).to.be.equal("SUCCESS");

			expect(storageMessageSet.calledOnce).to.be.true;
			const savedRes = JSON.parse(storageMessageSet.firstCall.lastArg);
			expect(savedRes).to.be.deep.equal({
				"version": "3.0",
				"dkim": [
					{
						"version": "2.1",
						"result": "SUCCESS",
						"sdid": "football.example.com",
						"auid": "@football.example.com",
						"selector": "test",
						"warnings": [],
						"keySecure": false,
						"timestamp": 1528637909,
						"expiration": null,
						"algorithmSignature": "rsa",
						"keyLength": 1024,
						"algorithmHash": "sha256",
						"signedHeaders": [
							"from",
							"to",
							"subject",
							"date",
							"message-id",
							"from",
							"subject",
							"date",
						],
					}, {
						"version": "2.1",
						"result": "SUCCESS",
						"sdid": "football.example.com",
						"auid": "@football.example.com",
						"selector": "brisbane",
						"warnings": [],
						"keySecure": false,
						"timestamp": 1528637909,
						"expiration": null,
						"algorithmSignature": "ed25519",
						"algorithmHash": "sha256",
						"signedHeaders": [
							"from",
							"to",
							"subject",
							"date",
							"message-id",
							"from",
							"subject",
							"date",
						],
					}]
			});
		});

		it("Don't store TEMPFAIL result", async function () {
			const queryFunktion = (/** @type {string} */ name) => {
				if (name === "brisbane._domainkey.football.example.com") {
					return Promise.resolve({
						rcode: DNS.RCODE.NoError,
						data: ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
						secure: false,
						bogus: false,
					});
				}
				throw new DKIM_TempError("DKIM_DNSERROR_SERVER_ERROR");
			};
			const verifier = new AuthVerifier(new Verifier(new KeyStore(queryFunktion)));
			const message = await createMessageHeader("rfc8463-A.3.eml");
			const res = await verifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[1]?.result).to.be.equal("TEMPFAIL");

			expect(storageMessageSet.notCalled).to.be.true;
		});

		it("Store BIMI result", async function () {
			await prefs.setValue("arh.read", true);

			const message = await createMessageHeader("bimi/rfc6376-A.2-with_bimi.eml");
			const res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(1);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");

			expect(storageMessageSet.calledOnce).to.be.true;
			const savedRes = JSON.parse(storageMessageSet.firstCall.lastArg);
			expect(savedRes).to.be.deep.equal({
				"version": "3.1",
				"dkim": [
					{
						"version": "2.1",
						"result": "SUCCESS",
						"sdid": "example.com",
						"auid": "joe@football.example.com",
						"selector": "brisbane",
						"warnings": [],
						"keySecure": false,
						"timestamp": null,
						"expiration": null,
						"algorithmSignature": "rsa",
						"keyLength": 1024,
						"algorithmHash": "sha256",
						"signedHeaders": [
							"received",
							"from",
							"to",
							"subject",
							"date",
							"message-id",
						],
					}
				],
				"spf": [],
				"dmarc": [],
				"bimiIndicator": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiICBzdGFuZGFsb25lPSJ5ZXMiPz4KPHN2ZyB2ZXJzaW9uPSIxLjIiIGJhc2VQcm9maWxlPSJ0aW55LXBzIiB2aWV3Qm94PSIwIDAgMTAwIDEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHRpdGxlPkV4YW1wbGU8L3RpdGxlPgo8Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI0MCIgc3Ryb2tlPSJibGFjayIgc3Ryb2tlLXdpZHRoPSIzIiBmaWxsPSJyZWQiIC8+Cjwvc3ZnPg=="
			});
		});
	});

	describe("loading of results", function () {
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
					properties: { smtp: {}, header: {}, body: {}, policy: {} },
				}],
				dmarc: [{
					method: "dmarc",
					method_version: 1,
					result: "fail",
					properties: { smtp: {}, header: {}, body: {}, policy: {} },
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
					properties: { smtp: {}, header: {}, body: {}, policy: {} },
				}],
			};
			res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0]?.res_num).to.be.equal(30);
			expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
			expect(res.dkim[0]?.result_str).to.be.equal("Invalid (Signature has an unsupported version)");

			expect(res.dmarc && res.dmarc[0]?.result).to.be.equal("pass");
		});

		it("loading SavedAuthResult 3.1 with BIMI result", async function () {
			storedData = {
				"version": "3.1",
				"dkim": [
					{
						"version": "2.0",
						"result": "SUCCESS",
						"sdid": "example.com",
						"auid": "joe@football.example.com",
						"selector": "brisbane",
						"warnings": [],
						"keySecure": false
					}
				],
				"spf": [],
				"dmarc": [],
				"bimiIndicator": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiICBzdGFuZGFsb25lPSJ5ZXMiPz4KPHN2ZyB2ZXJzaW9uPSIxLjIiIGJhc2VQcm9maWxlPSJ0aW55LXBzIiB2aWV3Qm94PSIwIDAgMTAwIDEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHRpdGxlPkV4YW1wbGU8L3RpdGxlPgo8Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI0MCIgc3Ryb2tlPSJibGFjayIgc3Ryb2tlLXdpZHRoPSIzIiBmaWxsPSJyZWQiIC8+Cjwvc3ZnPg=="
			};
			const res = await authVerifier.verify(createFakeMessageHeader());
			expect(res.dkim[0]?.res_num).to.be.equal(10);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.favicon).to.be.a("string").and.satisfy(
				(/** @type {string} */ favicon) => favicon.startsWith("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiICBzdGFuZGFsb25l"));
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

		// eslint-disable-next-line complexity
		it("Failure because of wrong SDID keeps signature meta data", async function () {
			const message = await createMessageHeader("rfc6376-A.2.eml");

			let res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(1);
			expect(res.dkim[0]?.res_num).to.be.equal(10);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
			expect(res.dkim[0]?.warnings).to.be.empty;
			expect(res.dkim[0]?.sdid).to.be.equal("example.com");
			expect(res.dkim[0]?.auid).to.be.equal("joe@football.example.com");
			expect(res.dkim[0]?.selector).to.be.equal("brisbane");
			expect(res.dkim[0]?.timestamp).to.be.equal(null);
			expect(res.dkim[0]?.expiration).to.be.equal(null);
			expect(res.dkim[0]?.algorithmSignature).to.be.equal("rsa");
			expect(res.dkim[0]?.algorithmHash).to.be.equal("sha256");
			expect(res.dkim[0]?.keyLength).to.be.equal(1024);
			expect(res.dkim[0]?.signedHeaders).to.be.deep.equal([
				"received",
				"from",
				"to",
				"subject",
				"date",
				"message-id",
			]);

			await prefs.setValue("policy.signRules.enable", true);
			await SignRules.addRule("example.com", null, "*", "foo.com", SignRules.TYPE.ALL);

			res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(1);
			expect(res.dkim[0]?.res_num).to.be.equal(30);
			expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
			expect(res.dkim[0]?.result_str).to.be.equal("Invalid (Wrong signer (should be foo.com))");
			expect(res.dkim[0]?.warnings).to.be.empty;
			expect(res.dkim[0]?.sdid).to.be.equal("example.com");
			expect(res.dkim[0]?.auid).to.be.equal("joe@football.example.com");
			expect(res.dkim[0]?.selector).to.be.equal("brisbane");
			expect(res.dkim[0]?.timestamp).to.be.equal(null);
			expect(res.dkim[0]?.expiration).to.be.equal(null);
			expect(res.dkim[0]?.algorithmSignature).to.be.equal("rsa");
			expect(res.dkim[0]?.algorithmHash).to.be.equal("sha256");
			expect(res.dkim[0]?.keyLength).to.be.equal(1024);
			expect(res.dkim[0]?.signedHeaders).to.be.deep.equal([
				"received",
				"from",
				"to",
				"subject",
				"date",
				"message-id",
			]);
		});
	});

	describe("ARH header", function () {
		it("spf and dkim result", async function () {
			const message = await createMessageHeader("arh/rfc6376-A.2-arh-valid.eml");
			let res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(1);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.spf).to.be.equal(undefined);

			await prefs.setValue("dkim.enable", false);

			res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(1);
			expect(res.dkim[0]?.result).to.be.equal("none");

			await prefs.setValue("arh.read", true);

			res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(1);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect((res.spf ?? [])[0]?.result).to.be.equal("pass");
		});

		it("relaxed parsing", async function () {
			const message = await createMessageHeader("arh/rfc6376-A.2-arh-valid_relaxed.eml");
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
				const message = await createMessageHeader("arh/rfc6376-A.2-arh-valid.eml");
				let res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.warnings_str).to.be.empty;
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");

				await prefs.setValue("arh.replaceAddonResult", false);

				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("none");
				const arhDkim = res.arh?.dkim ?? [];
				expect(arhDkim.length).to.be.equal(1);
				expect(arhDkim[0]?.sdid).to.be.equal("example.com");
				expect(arhDkim[0]?.auid).to.be.undefined;
				expect(arhDkim[0]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(arhDkim[0]?.warnings_str).to.be.empty;
			});

			it("DKIM pass with only AUID", async function () {
				// E.g. Google only includes the AUID.
				// Extracting the SDID from the AUID is only a heuristic, so the wrong SDID is expected.
				const message = await createMessageHeader("arh/rfc6376-A.2-arh-valid-auid.eml");
				let res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.warnings_str).to.be.empty;
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by football.example.com)");
				expect(res.dkim[0]?.sdid).to.be.equal("football.example.com");
				expect(res.dkim[0]?.auid).to.be.equal("joe@football.example.com");

				await prefs.setValue("arh.replaceAddonResult", false);

				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("none");
				const arhDkim = res.arh?.dkim ?? [];
				expect(arhDkim.length).to.be.equal(1);
				expect(arhDkim[0]?.sdid).to.be.equal("football.example.com");
				expect(arhDkim[0]?.auid).to.be.equal("joe@football.example.com");
				expect(arhDkim[0]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[0]?.result_str).to.be.equal("Valid (Signed by football.example.com)");
				expect(arhDkim[0]?.warnings_str).to.be.empty;
			});

			it("DKIM pass with both SDID and AUID", async function () {
				const message = await createMessageHeader("arh/rfc6376-A.2-arh-valid-sdid_and_auid.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.warnings_str).to.be.empty;
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("joe@football.example.com");
			});

			it("DKIM pass with no SDID or AUID", async function () {
				const message = await createMessageHeader("arh/rfc6376-A.2-arh-valid-no_sdid_or_auid.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by undefined)");
				expect(res.dkim[0]?.warnings_str).to.be.deep.equal(["From is not in the signing domain"]);
				expect(res.dkim[0]?.sdid).to.be.undefined;
				expect(res.dkim[0]?.auid).to.be.undefined;
			});

			it("From domain is not in the SDID", async function () {
				// From: joe@football.example.com
				const message = await createMessageHeader("arh/alignment-from_not_in_sdid.eml");
				let res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.sdid).to.be.equal("unrelated.com");
				expect(res.dkim[0]?.auid).to.be.equal("@unrelated.com");
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by unrelated.com)");
				expect(res.dkim[0]?.warnings_str).to.be.deep.equal(["From is not in the signing domain"]);

				await prefs.setValue("arh.replaceAddonResult", false);

				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("none");
				const arhDkim = res.arh?.dkim ?? [];
				expect(arhDkim.length).to.be.equal(1);
				expect(arhDkim[0]?.sdid).to.be.equal("unrelated.com");
				expect(arhDkim[0]?.auid).to.be.undefined;
				expect(arhDkim[0]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[0]?.result_str).to.be.equal("Valid (Signed by unrelated.com)");
				expect(arhDkim[0]?.warnings_str).to.be.empty;
			});

			it("AUID is not in the SDID", async function () {
				const message = await createMessageHeader("arh/alignment-auid_not_in_sdid.eml");
				let res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.sdid).to.be.equal("example.net");
				expect(res.dkim[0]?.auid).to.be.equal("joe@football.example.com");
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid (Signature is ill-formed)");

				await prefs.setValue("error.detailedReasons", true);

				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.sdid).to.be.equal("example.net");
				expect(res.dkim[0]?.auid).to.be.equal("joe@football.example.com");
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid (AUID is not in a subdomain of SDID)");

				await prefs.setValue("arh.replaceAddonResult", false);

				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("none");
				const arhDkim = res.arh?.dkim ?? [];
				expect(arhDkim.length).to.be.equal(1);
				expect(arhDkim[0]?.sdid).to.be.equal("example.net");
				expect(arhDkim[0]?.auid).to.be.equal("joe@football.example.com");
				expect(arhDkim[0]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[0]?.warnings_str).to.be.empty;
			});

			it("DKIM fail with reason", async function () {
				const message = await createMessageHeader("arh/rfc6376-A.2-arh-failed.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid (bad signature)");
			});

			it("DKIM fail without reason", async function () {
				const message = await createMessageHeader("arh/rfc6376-A.2-arh-failed-no_reason.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid");
			});

			it("DKIM results should be sorted", async function () {
				const message = await createMessageHeader("arh/multiple_dkim_results.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(7);
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
				const message = await createMessageHeader("arh/rfc6376-A.2-arh-valid-a_tag.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.warnings_str).to.be.empty;
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");
				expect(res.dkim[0]?.algorithmSignature).to.be.equal("rsa");
				expect(res.dkim[0]?.algorithmHash).to.be.equal("sha256");
			});

			it("With insecure signature algorithm", async function () {
				const message = await createMessageHeader("arh/rfc6376-A.2-arh-valid-a_tag_sha1.eml");

				let res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.warnings_str).to.be.deep.equal(["Insecure signature algorithm"]);
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");
				expect(res.dkim[0]?.algorithmSignature).to.be.equal("rsa");
				expect(res.dkim[0]?.algorithmHash).to.be.equal("sha1");

				prefs.setValue("error.algorithm.sign.rsa-sha1.treatAs", 0);
				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid (Insecure signature algorithm)");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");
				expect(res.dkim[0]?.algorithmSignature).to.be.equal("rsa");
				expect(res.dkim[0]?.algorithmHash).to.be.equal("sha1");

				prefs.setValue("error.algorithm.sign.rsa-sha1.treatAs", 2);
				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result_str).to.be.equal("Valid (Signed by example.com)");
				expect(res.dkim[0]?.warnings_str).to.be.empty;
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
				expect(res.dkim[0]?.auid).to.be.equal("@example.com");
				expect(res.dkim[0]?.algorithmSignature).to.be.equal("rsa");
				expect(res.dkim[0]?.algorithmHash).to.be.equal("sha1");
			});

			it("Sign rules should check SDID", async function () {
				const fakePayPalMessage = await createMessageHeader("arh/fakePayPal.eml");
				let res = await authVerifier.verify(fakePayPalMessage);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.warnings_str).to.be.deep.equal(["From is not in the signing domain"]);

				await prefs.setValue("policy.signRules.enable", true);

				res = await authVerifier.verify(fakePayPalMessage);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("PERMFAIL");
				expect(res.dkim[0]?.result_str).to.be.equal("Invalid (Wrong signer (should be paypal.com))");
			});
		});

		describe("Trust only specific ARHs", function () {
			beforeEach(async function () {
				await prefs.setValue("arh.read", true);
			});

			it("From the same and different authserv_id", async function () {
				const message = await createMessageHeader("arh/multiple_arh-same_and_different_authserv.eml");

				let res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(3);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.sdid).to.be.equal("football.example.com");
				expect(res.dkim[1]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[1]?.sdid).to.be.equal("example.com");
				expect(res.dkim[2]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[2]?.sdid).to.be.equal("last.example.com");
				expect((res.spf ?? [])[0]?.result).to.be.equal("pass");

				await prefs.setValue("arh.replaceAddonResult", false);

				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("none");
				const arhDkim = res.arh?.dkim ?? [];
				expect(arhDkim.length).to.be.equal(3);
				expect(arhDkim[0]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[0]?.sdid).to.be.equal("example.com");
				expect(arhDkim[1]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[1]?.sdid).to.be.equal("football.example.com");
				expect(arhDkim[2]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[2]?.sdid).to.be.equal("last.example.com");
				expect((res.spf ?? [])[0]?.result).to.be.equal("pass");
			});

			it("Newest ARH has no result", async function () {
				const message = await createMessageHeader("arh/multiple_arh-newest_no_result.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
			});

			it("Newest ARH has an unknown method", async function () {
				const message = await createMessageHeader("arh/multiple_arh-newest_unknown_method.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
			});

			it("Newest ARH has a parsing error in the method", async function () {
				const message = await createMessageHeader("arh/multiple_arh-newest_parsing_error_01.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.sdid).to.be.equal("example.com");
			});

			it("Newest ARH has a parsing error in the authserv_id", async function () {
				const message = await createMessageHeader("arh/multiple_arh-newest_parsing_error_02.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("none");
			});

			it("Newest ARH has no authserv_id", async function () {
				const message = await createMessageHeader("arh/multiple_arh-newest_no_authserv.eml");
				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("none");
			});

			it("Trust a specific authserv_id", async function () {
				await prefs.setAccountValue("arh.allowedAuthserv", "fakeAccount", "example.net");
				const message = await createMessageHeader("arh/multiple_arh-same_and_different_authserv.eml");

				let res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(3);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.sdid).to.be.equal("football.example.com");
				expect(res.dkim[1]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[1]?.sdid).to.be.equal("example.com");
				expect(res.dkim[2]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[2]?.sdid).to.be.equal("last.example.com");
				expect((res.spf ?? [])[0]?.result).to.be.equal("pass");

				await prefs.setValue("arh.replaceAddonResult", false);

				res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(1);
				expect(res.dkim[0]?.result).to.be.equal("none");
				const arhDkim = res.arh?.dkim ?? [];
				expect(arhDkim.length).to.be.equal(3);
				expect(arhDkim[0]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[0]?.sdid).to.be.equal("example.com");
				expect(arhDkim[1]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[1]?.sdid).to.be.equal("football.example.com");
				expect(arhDkim[2]?.result).to.be.equal("SUCCESS");
				expect(arhDkim[2]?.sdid).to.be.equal("last.example.com");
				expect((res.spf ?? [])[0]?.result).to.be.equal("pass");
			});

			it("Trust an authserv_id domain", async function () {
				await prefs.setAccountValue("arh.allowedAuthserv", "fakeAccount", "@example.net");
				const message = await createMessageHeader("arh/multiple_arh-same_and_different_authserv.eml");

				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(4);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.sdid).to.be.equal("football.example.com");
				expect(res.dkim[1]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[1]?.sdid).to.be.equal("example.com");
				expect(res.dkim[2]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[2]?.sdid).to.be.equal("foo.example.com");
				expect(res.dkim[3]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[3]?.sdid).to.be.equal("last.example.com");
				expect((res.spf ?? [])[0]?.result).to.be.equal("pass");
			});

			it("Trust multiple authserv_id", async function () {
				await prefs.setAccountValue("arh.allowedAuthserv", "fakeAccount", "foo.example.net unrelated.com");
				const message = await createMessageHeader("arh/multiple_arh-same_and_different_authserv.eml");

				const res = await authVerifier.verify(message);
				expect(res.dkim.length).to.be.equal(2);
				expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[0]?.sdid).to.be.equal("foo.example.com");
				expect(res.dkim[1]?.result).to.be.equal("SUCCESS");
				expect(res.dkim[1]?.sdid).to.be.equal("unrelated.com");
				expect(res.spf).to.be.empty;
			});
		});
	});

	describe("Valid messages", function () {
		it("Amazon received by Fastmail", async function () {
			const message = await createMessageHeader("original/Fastmail from Amazon - Verify your new Amazon account.eml");
			const res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(2);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.warnings).to.be.empty;
		});

		it("CNN received by Fastmail", async function () {
			let message = await createMessageHeader("original/Fastmail from CNN - Thanks for subscribing to 5 Things.eml");
			let res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(1);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.warnings).to.be.empty;

			message = await createMessageHeader("original/Fastmail from CNN - Welcome to CNN Breaking News.eml");
			res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(1);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.warnings).to.be.empty;
		});

		it("Fastmail received by Fastmail", async function () {
			let message = await createMessageHeader("original/Fastmail from Fastmail - How to keep your email private.eml");
			let res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(2);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.warnings).to.be.empty;

			message = await createMessageHeader("original/Fastmail from Fastmail - Welcome! Get set up in 3 steps..eml");
			res = await authVerifier.verify(message);
			expect(res.dkim.length).to.be.equal(2);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.warnings).to.be.empty;
		});
	});

	describe("Invalid messages", function () {
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

	describe("BIMI", function () {
		beforeEach(async function () {
			await prefs.setValue("arh.read", true);
		});

		it("RFC 6376 example with added BIMI", async function () {
			const message = await createMessageHeader("bimi/rfc6376-A.2-with_bimi.eml");
			const res = await authVerifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.favicon).to.be.a("string").and.satisfy(
				(/** @type {string} */ favicon) => favicon.startsWith("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiICBzdGFuZGFsb25l"));
		});

		it("Amazon received by Fastmail", async function () {
			await prefs.setValue("arh.relaxedParsing", true);

			const message = await createMessageHeader("original/Fastmail from Amazon - Verify your new Amazon account.eml");
			const res = await authVerifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.favicon).to.be.a("string").and.satisfy(
				(/** @type {string} */ favicon) => favicon.startsWith("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Inllcy"));
		});

		it("CNN received by Fastmail", async function () {
			await prefs.setValue("arh.relaxedParsing", true);

			const message = await createMessageHeader("original/Fastmail from CNN - Welcome to CNN Breaking News.eml");
			const res = await authVerifier.verify(message);
			expect(res.dkim[0]?.result).to.be.equal("SUCCESS");
			expect(res.dkim[0]?.favicon).to.be.a("string").and.satisfy(
				(/** @type {string} */ favicon) => favicon.startsWith("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCEtLSBHZW5lcmF0b3"));
		});
	});
});
