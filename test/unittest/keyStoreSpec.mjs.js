/**
 * Copyright (c) 2021;2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */

import KeyStore, { KeyDb } from "../../modules/dkim/keyStore.mjs.js";
import expect, { expectAsyncDkimSigError } from "../helpers/chaiUtils.mjs.js";
import DNS from "../../modules/dns.mjs.js";
import { hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import sinon from "../helpers/sinonUtils.mjs.js";

describe("Key store [unittest]", function () {
	before(async function () {
		if (!hasWebExtensions) {
			// eslint-disable-next-line no-invalid-this
			this.skip();
		}
		await prefs.init();
	});

	beforeEach(async function () {
		await prefs.clear();
		await KeyDb.clear();
	});

	describe("KeyDb", function () {
		it("store and fetch", async function () {
			await KeyDb.store("domainA", "selector1", "key1", false);
			await KeyDb.store("domainA", "selector2", "key2", true);
			await KeyDb.store("domainB", "selector", "key3", false);
			const key1 = await KeyDb.fetch("domainA", "selector1");
			expect(key1).is.deep.equal({ key: "key1", secure: false });
			const key2 = await KeyDb.fetch("domainA", "selector2");
			expect(key2).is.deep.equal({ key: "key2", secure: true });
			const key3 = await KeyDb.fetch("domainB", "selector");
			expect(key3).is.deep.equal({ key: "key3", secure: false });
			const key4 = await KeyDb.fetch("domain", "selector");
			expect(key4).is.null;
		});
		it("mark as secure", async function () {
			await KeyDb.store("domainA", "selector1", "key1", false);
			await KeyDb.markAsSecure("domainA", "selector1");
			const key1 = await KeyDb.fetch("domainA", "selector1");
			expect(key1).is.deep.equal({ key: "key1", secure: true });
		});
		it("update", async function () {
			await KeyDb.store("domainA", "selector1", "key1", false);
			await KeyDb.update(1, "sdid", "domainNew");
			const keyOld = await KeyDb.fetch("domainA", "selector1");
			expect(keyOld).is.null;
			const keyNew = await KeyDb.fetch("domainNew", "selector1");
			expect(keyNew).is.deep.equal({ key: "key1", secure: false });
		});
		it("delete", async function () {
			await KeyDb.store("domainA", "selector1", "key1", false);
			await KeyDb.store("domainB", "selector1", "key2", false);
			await KeyDb.store("domainC", "selector1", "key3", false);

			let key = await KeyDb.fetch("domainB", "selector1");
			expect(key).is.not.null;
			await KeyDb.delete(2);
			key = await KeyDb.fetch("domainB", "selector1");
			expect(key).is.null;

			key = await KeyDb.fetch("domainC", "selector1");
			expect(key).is.not.null;
			await KeyDb.delete(null, "domainC", "selector1");
			key = await KeyDb.fetch("domainC", "selector1");
			expect(key).is.null;
		});
		it("keys should survive clearing of preferences", async function () {
			await KeyDb.store("domainA", "selector1", "key1", false);
			await KeyDb.store("domainB", "selector1", "key2", false);
			await KeyDb.store("domainC", "selector1", "key3", false);

			const keyStore = (await browser.storage.local.get("keyStore")).keyStore;
			await KeyDb.clear();
			await browser.storage.local.set({ keyStore });

			prefs.clear();

			const key = await KeyDb.fetch("domainB", "selector1");
			expect(key).is.deep.equal({ key: "key2", secure: false });
		});
	});

	describe("KeyStore", function () {
		// @ts-expect-error
		const toDnsRes = record => Promise.resolve({
			data: [record],
			rcode: DNS.RCODE.NoError,
			secure: false,
			bogus: false,
		});
		/** @type {typeof DNS.txt} */
		const queryDnsTxt = name => {
			switch (name) {
				case "selector1._domainkey.example.com":
					return toDnsRes("key1");
				default:
					return Promise.resolve({
						data: null,
						rcode: DNS.RCODE.NXDomain,
						secure: false,
						bogus: false,
					});
			}
		};

		/** @type {sinon.SinonStub} */
		let fakeQueryDnsTxt;
		before(function () {
			fakeQueryDnsTxt = sinon.stub();
		});

		beforeEach(function () {
			fakeQueryDnsTxt.reset();
			fakeQueryDnsTxt.callsFake(queryDnsTxt);
		});

		it("storing disabled", async function () {
			const keyStore = new KeyStore(fakeQueryDnsTxt);

			let key = await keyStore.fetchKey("example.com", "selector1");
			expect(key).is.deep.equal({ key: "key1", secure: false });

			key = await keyStore.fetchKey("example.com", "selector1");
			expect(key).is.deep.equal({ key: "key1", secure: false });

			expect(fakeQueryDnsTxt.calledTwice).is.true;
		});
		it("storing enabled", async function () {
			prefs.setValue("key.storing", KeyStore.KEY_STORING.STORE);
			const keyStore = new KeyStore(fakeQueryDnsTxt);

			let key = await keyStore.fetchKey("example.com", "selector1");
			expect(key).is.deep.equal({ key: "key1", secure: false });

			key = await keyStore.fetchKey("example.com", "selector1");
			expect(key).is.deep.equal({ key: "key1", secure: false });

			expect(fakeQueryDnsTxt.calledOnce).is.true;
		});
		it("storing enabled with compare", async function () {
			prefs.setValue("key.storing", KeyStore.KEY_STORING.COMPARE);
			const keyStore = new KeyStore(fakeQueryDnsTxt);

			fakeQueryDnsTxt.onThirdCall().returns(toDnsRes("newKey"));

			let key = await keyStore.fetchKey("example.com", "selector1");
			expect(key).is.deep.equal({ key: "key1", secure: false });
			key = await keyStore.fetchKey("example.com", "selector1");
			expect(key).is.deep.equal({ key: "key1", secure: false });

			const keyPromise = keyStore.fetchKey("example.com", "selector1");
			await expectAsyncDkimSigError(keyPromise, "DKIM_POLICYERROR_KEYMISMATCH");

			expect(fakeQueryDnsTxt.calledThrice).is.true;
		});
	});
});
