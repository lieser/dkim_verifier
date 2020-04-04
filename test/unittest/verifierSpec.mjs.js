/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint no-unused-vars: ["error", { "varsIgnorePattern": "VerifierModule" }]*/

import "../helpers/fetchKey.mjs.js";
import Verifier, * as VerifierModule from "../../modules/dkim/verifier.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { readTextFile } from "../helpers/testUtils.mjs.js";

/**
 * Verify DKIM for the given eml file.
 *
 * @param {string} file - path to file relative to test data directory
 * @returns {Promise<VerifierModule.dkimResultV2>}
 */
async function verifyEmlFile(file) {
	const msgPlain = await readTextFile(file);
	const msgParsed = MsgParser.parseMsg(msgPlain);
	const msg = {
		headerFields: msgParsed.headers,
		bodyPlain: msgParsed.body,
		from: MsgParser.parseAddressingHeader(msgParsed.headers.get("from")[0]),
		listId: "",
		DKIMSignPolicy: {},
	};
	const verifier = new Verifier();
	return verifier.verify(msg);
}

describe("DKIM Verifier [unittest]", function () {
	describe("RFC 6376 Appendix A Example", function () {
		it("valid", async function () {
			const res = await verifyEmlFile("rfc6376-A.2.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0].result).to.be.equal("SUCCESS");
		});
		it("body modified", async function () {
			const res = await verifyEmlFile("rfc6376-A.2-body_modified.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0].result).to.be.equal("PERMFAIL");
			expect(res.signatures[0].errorType).to.be.equal("DKIM_SIGERROR_CORRUPT_BH");
		});
		it("header subject modified", async function () {
			const res = await verifyEmlFile("rfc6376-A.2-header_subject_modified.eml");
			expect(res.signatures.length).to.be.equal(1);
			expect(res.signatures[0].result).to.be.equal("PERMFAIL");
			expect(res.signatures[0].errorType).to.be.equal("DKIM_SIGERROR_BADSIG");
		});
	});
});
