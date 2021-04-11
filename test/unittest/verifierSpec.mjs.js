/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint no-unused-vars: ["error", { "varsIgnorePattern": "VerifierModule" }]*/

import "../helpers/dnsStub.mjs.js";
import "../helpers/initWebExtensions.mjs.js";
import Verifier, * as VerifierModule from "../../modules/dkim/verifier.mjs.js";
import KeyStore from "../../modules/dkim/keyStore.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { queryDnsTxt } from "../helpers/dnsStub.mjs.js";
import { readTestFile } from "../helpers/testUtils.mjs.js";

/**
 * Verify DKIM for the given eml file.
 *
 * @param {string} file - path to file relative to test data directory
 * @returns {Promise<VerifierModule.dkimResultV2>}
 */
async function verifyEmlFile(file) {
	const msgPlain = await readTestFile(file);
	const msgParsed = MsgParser.parseMsg(msgPlain);
	const from = msgParsed.headers.get("from");
	if (!from) {
		throw new Error("eml file does not contain a From header");
	}
	const msg = {
		headerFields: msgParsed.headers,
		bodyPlain: msgParsed.body,
		from: MsgParser.parseFromHeader(from[0]),
	};
	const verifier = new Verifier(new KeyStore(queryDnsTxt));
	return verifier.verify(msg);
}

describe("DKIM Verifier [unittest]", function () {
	describe("RFC 6376 Appendix A Example", function () {
		it("valid", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0].result).to.be.equal("SUCCESS");
			expect(res.signatures[0].warnings).to.be.empty;
			expect(res.signatures[0].sdid).to.be.equal("example.com");
			expect(res.signatures[0].auid).to.be.equal("joe@football.example.com");
			expect(res.signatures[0].selector).to.be.equal("brisbane");
		});
		it("body modified", async function () {
			const res = await verifyEmlFile("rfc6376-A.2-body_modified.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0].result).to.be.equal("PERMFAIL");
			expect(res.signatures[0].errorType).to.be.equal("DKIM_SIGERROR_CORRUPT_BH");
			expect(res.signatures[0].sdid).to.be.equal("example.com");
		});
		it("header subject modified", async function () {
			const res = await verifyEmlFile("rfc6376-A.2-header_subject_modified.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0].result).to.be.equal("PERMFAIL");
			expect(res.signatures[0].errorType).to.be.equal("DKIM_SIGERROR_BADSIG");
			expect(res.signatures[0].sdid).to.be.equal("example.com");
		});
		it("missing v", async function () {
			const res = await verifyEmlFile("rfc6376-A.2-ill_formed-missing_v.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0].result).to.be.equal("PERMFAIL");
			expect(res.signatures[0].errorType).to.be.equal("DKIM_SIGERROR_MISSING_V");
			expect(res.signatures[0].sdid).to.be.undefined;
		});
	});
	describe("Signature warnings", function () {
		it("From address is not in the SDID ", async function () {
			// TODO: instead of artificial test, add test mail there this is the case
			const msgPlain = await readTestFile("rfc6376-A.2.eml");
			const msgParsed = MsgParser.parseMsg(msgPlain);
			const msg = {
				headerFields: msgParsed.headers,
				bodyPlain: msgParsed.body,
				from: "foo@bar.com",
			};
			const verifier = new Verifier(new KeyStore(queryDnsTxt));
			const res = await verifier.verify(msg);
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0].result).to.be.equal("SUCCESS");
			expect(res.signatures[0].warnings).to.be.an('array').
				that.deep.includes({name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID"});
		});
	});
});
