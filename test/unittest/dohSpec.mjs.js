/**
 * Copyright (c) 2026 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import expect, { expectAsyncDkimTempError } from "../helpers/chaiUtils.mjs.js";
import DNS from "../../modules/dns.mjs.js";
import Logging from "../../modules/logging.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import txt from "../../modules/doh.mjs";

/** @import {QueryFunction} from "../../modules/doh.mjs" */

describe("DNS over HTTPS", function () {
	before(async function () {
		await prefs.init();
	});

	afterEach(async function () {
		await prefs.clear();
	});

	/**
	 * @param {string} expectedQuery - Hex encoded expected query.
	 * @param {string} response - Hex encoded response.
	 * @returns {QueryFunction}
	 */
	function CreateQueryFunction(expectedQuery, response) {
		/** @type {QueryFunction} */
		const queryFunction = (query) => {
			// @ts-expect-error
			expect(query.toHex()).to.be.equal(expectedQuery);
			// @ts-expect-error
			const responseBytes = Uint8Array.fromHex(response);
			return Promise.resolve(responseBytes);
		};
		return queryFunction;
	}

	it("Existing record", async function () {
		const queryFunction = CreateQueryFunction(
			"000001200001000000000000067066323032330a5f646f6d61696e6b65790667697468756203636f6d0000100001",
			"000081800001000100000000067066323032330a5f646f6d61696e6b65790667697468756203636f6d0000100001c00c0010000100" +
			"000db700ebea763d444b494d313b206b3d7273613b20703d4d4947664d413047435371475349623344514542415155414134474e41" +
			"44434269514b42675143636d7a6d795a5a2b7663417a3074464e394e49424a7565317754584477664d70306d6c375859735a686257" +
			"796d4748477357497641392f65644c6e314841334b314730494b565166584b6c6f4f686b4461424952543558716d49376130387677" +
			"6d5a6d515031325638704d5344354571737841475433614a79796d474a4363637942484c7a575643714e486876764439516b796232" +
			"5577557746484d566f6c374c41324d414c7759622b51494441514142"
		);
		const res = await txt("pf2023._domainkey.github.com", queryFunction);
		expect(res.rcode).to.be.equal(DNS.RCODE.NoError);
		expect(res.data?.length).to.be.equal(1);
		expect((res.data ?? [])[0]).to.be.equal(
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcmzmyZZ+vcAz0tFN9NIBJue1wTXDwfMp0ml7XYsZhbWymGHGs" +
			"WIvA9/edLn1HA3K1G0IKVQfXKloOhkDaBIRT5XqmI7a08vwmZmQP12V8pMSD5EqsxAGT3aJyymGJCccyBHLzWVCqNHhvvD9Qkyb2UwUwFH" +
			"MVol7LA2MALwYb+QIDAQAB");
		expect(res.secure).to.be.equal(false);
		expect(res.bogus).to.be.equal(false);
	});

	it("No record", async function () {
		const queryFunction = CreateQueryFunction(
			"000001200001000000000000067066323031340a5f646f6d61696e6b65790667697468756203636f6d0000100001",
			"000081830001000000010000067066323031340a5f646f6d61696e6b65790667697468756203636f6d0000100001c01e0006000100" +
			"000dd7003504646e733103703038056e736f6e65036e6574000a686f73746d6173746572c04362bbb2370000a8c000001c20001275" +
			"0000000e10"
		);
		const res = await txt("pf2014._domainkey.github.com", queryFunction);
		expect(res.rcode).to.be.equal(DNS.RCODE.NXDomain);
		expect(res.data).to.be.null;
		expect(res.secure).to.be.equal(false);
		expect(res.bogus).to.be.equal(false);
	});

	it("DNSSEC and record containing multiple strings", async function () {
		const queryFunction = CreateQueryFunction(
			"00000120000100000000000004323031370a5f646f6d61696e6b657906706f7374656f0264650000100001",
			"000081a0000100010000000004323031370a5f646f6d61696e6b657906706f7374656f0264650000100001c00c00100001000000ef" +
			"01a518763d444b494d313b206b3d7273613b20733d656d61696c3bfc703d4d494942496a414e42676b71686b694739773042415145" +
			"4641414f43415138414d49494243674b43415145417350585154394178504e64447157315541677a746d574f474f4e35436e6f7665" +
			"414d4f696d57613655534b345a446c64744c5232546e387a6e66413241372f37542f644b38532b594a53757056592f4c6638496f6c" +
			"45344e554b495242646d4f2f2f376d72624970625456392b64684c324a69376f7437507a6b4a4c612f735868696c5049456d73484a" +
			"6e756e457070686b58576c5477544a70317a326f38464f764a697071776c6f48365730544f45544856346c5762322f6c4f335a6b30" +
			"6c2f4a346364677171537045457a4d8e43785564387653593643506376372b646d6a6e535549717554584a6138434d676b392f7632" +
			"5147775777694b4b44727a64516d5848634b54542f657571576f417561677672754b4e49483766774f724e4261482b4a7539593379" +
			"703357573443527839394a3532584c53353334566e386352416343387533767a396745424d6d677368485a6a4f77494441514142"
		);
		const res = await txt("2017._domainkey.posteo.de", queryFunction);
		expect(res.rcode).to.be.equal(DNS.RCODE.NoError);
		expect(res.data?.length).to.be.equal(1);
		expect((res.data ?? [])[0]).to.be.equal(
			"v=DKIM1; k=rsa; s=email;" +
			"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsPXQT9AxPNdDqW1UAgztmWOGON5CnoveAMOimWa6USK4ZDldtLR2Tn8znfA2" +
			"A7/7T/dK8S+YJSupVY/Lf8IolE4NUKIRBdmO//7mrbIpbTV9+dhL2Ji7ot7PzkJLa/sXhilPIEmsHJnunEpphkXWlTwTJp1z2o8FOvJipq" +
			"wloH6W0TOETHV4lWb2/lO3Zk0l/J4cdgqqSpEEzM" +
			"CxUd8vSY6CPcv7+dmjnSUIquTXJa8CMgk9/v2QGwWwiKKDrzdQmXHcKTT/euqWoAuagvruKNIH7fwOrNBaH+Ju9Y3yp3WW4CRx99J52XLS" +
			"534Vn8cRAcC8u3vz9gEBMmgshHZjOwIDAQAB"
		);
		expect(res.secure).to.be.equal(true);
		expect(res.bogus).to.be.equal(false);
	});

	it("Answer contains a CNAME record", async function () {
		const queryFunction = CreateQueryFunction(
			"00000120000100000000000007733135313333370a5f646f6d61696e6b657914626c61636b2d73686565702d726573656172636803" +
			"636f6d0000100001",
			"00008180000100020000000007733135313333370a5f646f6d61696e6b657914626c61636b2d73686565702d726573656172636803" +
			"636f6d0000100001c00c00050001000001b7001204646b696d07736d747032676f036e657400c0490010000100001b7f019cff763d" +
			"444b494d313b206b3d7273613b20703d4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243" +
			"674b43415145416e2f7a4b577638676558446c4a39725a6d74496657346552384d56716b4473666b6f516c6a763932714f76584e47" +
			"33453563326e2b34627056544666575471386359303267624a554c694743437046644d56756c326669554e324e412b484a33336956" +
			"4b48414e57773067524d364251412f2b566a48706a4f45567a6d6c617a6d675659617969785334385763322b505763643472306632" +
			"6b3872424662674c79744c554c515257375954313664734541626a6f6e6553534662465435433136339b48562f6e534d306a444947" +
			"30367a34675a2f66797a5a6e4279372b674a4b38733464444a78316d446e342f6f5675512b65412f514c7445653939677839657772" +
			"7648624c764930366a7839304d4939647379476f38476c764f51447772367243584833463550536b7874342f2b556c7161764b4273" +
			"75673267344966514850584c4d314e3561386c425673326353335a4f71763277494441514142"
		);
		const res = await txt("s151337._domainkey.black-sheep-research.com", queryFunction);
		expect(res.rcode).to.be.equal(DNS.RCODE.NoError);
		expect(res.data?.length).to.be.equal(1);
		expect((res.data ?? [])[0]).to.be.equal(
			"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/zKWv8geXDlJ9rZmtIfW4eR8MVqkDsfkoQljv92qOvX" +
			"NG3E5c2n+4bpVTFfWTq8cY02gbJULiGCCpFdMVul2fiUN2NA+HJ33iVKHANWw0gRM6BQA/+VjHpjOEVzmlazmgVYayixS48Wc2+PWcd4r0" +
			"f2k8rBFbgLytLULQRW7YT16dsEAbjoneSSFbFT5C163" +
			"HV/nSM0jDIG06z4gZ/fyzZnBy7+gJK8s4dDJx1mDn4/oVuQ+eA/QLtEe99gx9ewrvHbLvI06jx90MI9dsyGo8GlvOQDwr6rCXH3F5PSkxt" +
			"4/+UlqavKBsug2g4IfQHPXLM1N5a8lBVs2cS3ZOqv2wIDAQAB"
		);
		expect(res.secure).to.be.equal(false);
		expect(res.bogus).to.be.equal(false);
	});

	// eslint-disable-next-line mocha/no-pending-tests
	xdescribe("Online tests", function () {
		beforeEach(function () {
			Logging.setLogLevel(Logging.Level.All);
		});

		it("Existing record", async function () {
			const res = await txt("pf2023._domainkey.github.com");
			expect(res.rcode).to.be.equal(DNS.RCODE.NoError);
			expect(res.data?.length).to.be.equal(1);
			expect((res.data ?? [])[0]).to.be.equal(
				"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcmzmyZZ+vcAz0tFN9NIBJue1wTXDwfMp0ml7XYsZhbWym" +
				"GHGsWIvA9/edLn1HA3K1G0IKVQfXKloOhkDaBIRT5XqmI7a08vwmZmQP12V8pMSD5EqsxAGT3aJyymGJCccyBHLzWVCqNHhvvD9Qky" +
				"b2UwUwFHMVol7LA2MALwYb+QIDAQAB");
			expect(res.secure).to.be.equal(false);
			expect(res.bogus).to.be.equal(false);
		});

		it("No record", async function () {
			const res = await txt("pf2014._domainkey.github.com");
			expect(res.rcode).to.be.equal(DNS.RCODE.NXDomain);
			expect(res.data).to.be.null;
			expect(res.secure).to.be.equal(false);
			expect(res.bogus).to.be.equal(false);
		});

		it("DNSSEC and record containing multiple strings", async function () {
			const res = await txt("2017._domainkey.posteo.de");
			expect(res.rcode).to.be.equal(DNS.RCODE.NoError);
			expect(res.data?.length).to.be.equal(1);
			expect((res.data ?? [])[0]).to.be.equal(
				"v=DKIM1; k=rsa; s=email;" +
				"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsPXQT9AxPNdDqW1UAgztmWOGON5CnoveAMOimWa6USK4ZDldtLR2Tn8z" +
				"nfA2A7/7T/dK8S+YJSupVY/Lf8IolE4NUKIRBdmO//7mrbIpbTV9+dhL2Ji7ot7PzkJLa/sXhilPIEmsHJnunEpphkXWlTwTJp1z2o" +
				"8FOvJipqwloH6W0TOETHV4lWb2/lO3Zk0l/J4cdgqqSpEEzM" +
				"CxUd8vSY6CPcv7+dmjnSUIquTXJa8CMgk9/v2QGwWwiKKDrzdQmXHcKTT/euqWoAuagvruKNIH7fwOrNBaH+Ju9Y3yp3WW4CRx99J5" +
				"2XLS534Vn8cRAcC8u3vz9gEBMmgshHZjOwIDAQAB"
			);
			expect(res.secure).to.be.equal(true);
			expect(res.bogus).to.be.equal(false);
		});

		it("Answer contains a CNAME record", async function () {
			const res = await txt("s151337._domainkey.black-sheep-research.com");
			expect(res.rcode).to.be.equal(DNS.RCODE.NoError);
			expect(res.data?.length).to.be.equal(1);
			expect((res.data ?? [])[0]).to.be.equal(
				"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn/zKWv8geXDlJ9rZmtIfW4eR8MVqkDsfkoQljv92" +
				"qOvXNG3E5c2n+4bpVTFfWTq8cY02gbJULiGCCpFdMVul2fiUN2NA+HJ33iVKHANWw0gRM6BQA/+VjHpjOEVzmlazmgVYayixS48Wc2" +
				"+PWcd4r0f2k8rBFbgLytLULQRW7YT16dsEAbjoneSSFbFT5C163" +
				"HV/nSM0jDIG06z4gZ/fyzZnBy7+gJK8s4dDJx1mDn4/oVuQ+eA/QLtEe99gx9ewrvHbLvI06jx90MI9dsyGo8GlvOQDwr6rCXH3F5P" +
				"Skxt4/+UlqavKBsug2g4IfQHPXLM1N5a8lBVs2cS3ZOqv2wIDAQAB"
			);
			expect(res.secure).to.be.equal(false);
			expect(res.bogus).to.be.equal(false);
		});

		it("Server not rechable", async function () {
			await prefs.setValue("dns.doh.server", "https://dnsx.google/dns-query");

			const res = txt("pf2023._domainkey.github.com");
			await expectAsyncDkimTempError(res, "DKIM_DNSERROR_SERVER_ERROR");
		});

		it("URL not found (HTTP 404)", async function () {
			await prefs.setValue("dns.doh.server", "https://dns.google/dns-queryX");

			const res = txt("pf2023._domainkey.github.com");
			await expectAsyncDkimTempError(res, "DKIM_DNSERROR_UNKNOWN");
		});

		it("Normal HTML page", async function () {
			await prefs.setValue("dns.doh.server", "https://dns.google");

			const res = txt("pf2023._domainkey.github.com");
			await expectAsyncDkimTempError(res, "DKIM_DNSERROR_UNKNOWN");
		});
	});
});
