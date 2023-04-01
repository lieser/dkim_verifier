/**
 * Copyright (c) 2020;2022-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import expect, { expectAsyncDkimSigError, expectAsyncError } from "../helpers/chaiUtils.mjs.js";
import DkimCrypto from "../../modules/dkim/crypto.mjs.js";

describe("crypto [unittest]", function () {
	/**
	 * @param {string} str
	 * @param {number} index
	 * @param {string} replacement
	 * @returns {string}
	 */
	function strReplaceAt(str, index, replacement) {
		return str.substr(0, index) + replacement + str.substr(index + replacement.length);
	}

	describe("digest", function () {
		it("sha1", async function () {
			expect(
				await DkimCrypto.digest("sha1", "")
			).to.be.equal("2jmj7l5rSw0yVb/vlWAYkK/YBwk=");
			expect(
				await DkimCrypto.digest("sha1", "\r\n")
			).to.be.equal("uoq1oCgLlTqpdDX/iUbLy7J1Wic=");
		});
		it("sha256", async function () {
			expect(
				await DkimCrypto.digest("sha256", "")
			).to.be.equal("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
			expect(
				await DkimCrypto.digest("sha256", "\r\n")
			).to.be.equal("frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=");
		});
		it("8-bit", async function () {
			expect(
				await DkimCrypto.digest("sha256", "a test ð\u009f\u008d\u0095\r\n")
			).to.be.equal("bYcDq5OnCARcoHQv2Qhc9Jw8ZYXgw75R/Ku1CCT8qNA=");
		});
	});
	describe("verify RSA signature", function () {
		// RFC 6376 Appendix A Example
		const pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
			"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
			"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
			"MmPSPDdQPNUYckcQ2QIDAQAB";
		const signature = "AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB" +
			"4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut" +
			"KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV" +
			"4bmp/YzhwvcubU4=";
		const msg =
			"Received: from client1.football.example.com  [192.0.2.1]\r\n" +
			"      by submitserver.example.com with SUBMISSION;\r\n" +
			"      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)\r\n" +
			"From: Joe SixPack <joe@football.example.com>\r\n" +
			"To: Suzie Q <suzie@shopping.example.net>\r\n" +
			"Subject: Is dinner ready?\r\n" +
			"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
			"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n" +
			"DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;\r\n" +
			"      c=simple/simple; q=dns/txt; i=joe@football.example.com;\r\n" +
			"      h=Received : From : To : Subject : Date : Message-ID;\r\n" +
			"      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
			"      b=;";

		it("signature valid", async function () {
			const [valid, keyLength] = await DkimCrypto.verifyRSA(pubKey, "sha256", signature, msg);
			expect(valid).to.be.true;
			expect(keyLength).to.be.equal(1024);
		});
		it("invalid key", async function () {
			const res = DkimCrypto.verifyRSA(strReplaceAt(pubKey, 5, "x"), "sha256", signature, msg);
			await expectAsyncDkimSigError(res, "DKIM_SIGERROR_KEYDECODE");
		});
		it("invalid signature", async function () {
			const [valid] = await DkimCrypto.verifyRSA(pubKey, "sha256", strReplaceAt(signature, 5, "x"), msg);
			expect(valid).to.be.false;
		});
		it("invalid msg", async function () {
			const [valid] = await DkimCrypto.verifyRSA(pubKey, "sha256", signature, strReplaceAt(msg, 5, "x"));
			expect(valid).to.be.false;
		});
		it("wrong key", async function () {
			const github = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDaCCQ+CiOqRkMAM/Oi04Xjhnxv" +
			"3bXkTtA8KXt49RKQExLCmBxRpMp0PMMI73noKL/bZwEXljPO8HIfzG43ntPp1QRB" +
			"Upn1UEvbp1/rlWPUop3i1j6aUpjxYGHEEzgmT+ncLUBDEPO4n4Zzt36DG3ZcJaLh" +
			"vKtRkk2off5XD+BMvQIDAQAB";
			const [valid] = await DkimCrypto.verifyRSA(github, "sha256", signature, msg);
			expect(valid).to.be.false;
		});
		it("wrong hash algorithm", async function () {
			const [valid] = await DkimCrypto.verifyRSA(pubKey, "sha1", signature, msg);
			expect(valid).to.be.false;
		});
	});
	describe("verify Ed25519 signature", function () {
		// RFC 8463 Appendix A Example
		const pubKey = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
		const signature = "/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus" +
			"Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==";

		const msg =
			"from:Joe SixPack <joe@football.example.com>\r\n" +
			"to:Suzie Q <suzie@shopping.example.net>\r\n" +
			"subject:Is dinner ready?\r\n" +
			"date:Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
			"message-id:<20030712040037.46341.5F8J@football.example.com>\r\n" +
			"dkim-signature:v=1; a=ed25519-sha256; c=relaxed/relaxed;" +
			" d=football.example.com; i=@football.example.com;" +
			" q=dns/txt; s=brisbane; t=1528637909; h=from : to :" +
			" subject : date : message-id : from : subject : date;" +
			" bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;" +
			" b=";

		it("signature valid", async function () {
			const [valid, keyLength] = await DkimCrypto.verifyEd25519(pubKey, "sha256", signature, msg);
			expect(valid).to.be.true;
			expect(keyLength).to.be.equal(256);
		});
		it("invalid key", async function () {
			const res = DkimCrypto.verifyEd25519("11qYAYKxCrfVS/7TyWQ", "sha256", signature, msg);
			await expectAsyncError(res, Error);
		});
		it("invalid signature", async function () {
			const [valid] = await DkimCrypto.verifyEd25519(pubKey, "sha256", strReplaceAt(signature, 5, "x"), msg);
			expect(valid).to.be.false;
		});
		it("invalid msg", async function () {
			const [valid] = await DkimCrypto.verifyEd25519(pubKey, "sha256", signature, strReplaceAt(msg, 5, "x"));
			expect(valid).to.be.false;
		});
		it("wrong key", async function () {
			const [valid] = await DkimCrypto.verifyEd25519(strReplaceAt(pubKey, 5, "x"), "sha256", signature, msg);
			expect(valid).to.be.false;
		});
		it("wrong hash algorithm", async function () {
			const [valid] = await DkimCrypto.verifyEd25519(pubKey, "sha1", signature, msg);
			expect(valid).to.be.false;
		});
	});
});
