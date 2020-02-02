// @ts-check

/** @type{Chai.ExpectStatic} */
// @ts-ignore
const expect = globalThis.expect;

import DkimCrypto from "../../modules/dkim/crypto.mjs.js";

describe("crypt [unittest]", function () {
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
	});
});
