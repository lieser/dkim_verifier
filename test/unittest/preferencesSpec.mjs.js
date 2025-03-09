/**
 * Copyright (c) 2020-2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import expect, { expectAsyncError } from "../helpers/chaiUtils.mjs.js";
import pref, { StorageLocalPreferences } from "../../modules/preferences.mjs.js";
import { fakeBrowser } from "../helpers/initWebExtensions.mjs.js";
import sinon from "../helpers/sinonUtils.mjs.js";

describe("preferences [unittest]", function () {
	before(async function () {
		await pref.init();
	});

	beforeEach(async function () {
		await pref.clear();
	});

	describe("getValue", function () {
		it("get string", function () {
			expect(
				pref.getValue("dns.nameserver")
			).to.be.equal("8.8.8.8");
		});

		it("get number", function () {
			expect(
				pref.getValue("error.algorithm.rsa.weakKeyLength.treatAs")
			).to.be.equal(2);
		});

		it("get bool", function () {
			expect(
				pref.getValue("policy.signRules.enable")
			).to.be.false;
		});

		it("throw if not exist", function () {
			expect(
				() => pref.getValue("policy.xxx")
			).to.throw();
			expect(
				() => pref.getValue("policy.xxx.yyy")
			).to.throw();
			expect(
				() => pref.getValue("policy.signRules")
			).to.throw();
			expect(
				() => pref.getValue("policy.signRules.xxx")
			).to.throw();
			expect(
				() => pref.getValue("policy.signRules")
			).to.throw();
		});
	});

	describe("getBool/getNumber/getString", function () {
		it("get string", function () {
			expect(
				pref.getString("dns.nameserver")
			).to.be.equal("8.8.8.8");
		});

		it("get number", function () {
			expect(
				pref.getNumber("error.algorithm.rsa.weakKeyLength.treatAs")
			).to.be.equal(2);
		});

		it("get bool", function () {
			expect(
				pref.getBool("policy.signRules.enable")
			).to.be.false;
		});

		it("throw if not exist", function () {
			expect(
				() => pref.getBool("policy.xxx")
			).to.throw();
			expect(
				() => pref.getNumber("policy.xxx.yyy")
			).to.throw();
			expect(
				() => pref.getString("policy.signRules")
			).to.throw();
		});

		it("throw if unexpected type", function () {
			expect(
				() => pref.getBool("dns.proxy.type")
			).to.throw();
			expect(
				() => pref.getNumber("dns.proxy.type")
			).to.throw();
			expect(
				() => pref.getBool("error.algorithm.rsa.weakKeyLength.treatAs")
			).to.throw();
			expect(
				() => pref.getString("error.algorithm.rsa.weakKeyLength.treatAs")
			).to.throw();
			expect(
				() => pref.getNumber("display.favicon.show")
			).to.throw();
			expect(
				() => pref.getString("display.favicon.show")
			).to.throw();
		});
	});

	describe("getter access", function () {
		it("get string", function () {
			expect(
				pref["dns.nameserver"]
			).to.be.equal("8.8.8.8");
		});

		it("get number", function () {
			expect(
				pref["error.algorithm.rsa.weakKeyLength.treatAs"]
			).to.be.equal(2);
		});

		it("get bool", function () {
			expect(
				pref["policy.signRules.enable"]
			).to.be.false;
		});

		it("undefined if not exist", function () {
			expect(
				// @ts-expect-error
				pref["policy.xxx"]
			).to.be.undefined;
			expect(
				// @ts-expect-error
				pref["policy.xxx.yyy"]
			).to.be.undefined;
			expect(
				// @ts-expect-error
				pref["policy.signRules"]
			).to.be.undefined;
			expect(
				// @ts-expect-error
				pref["policy.signRules.xxx"]
			).to.be.undefined;
			expect(
				// @ts-expect-error
				pref["policy.signRules"]
			).to.be.undefined;
		});
	});

	describe("set value", function () {
		it("getter access after setting", function () {
			expect(
				pref["display.favicon.show"]
			).to.be.true;
			pref.setValue("display.favicon.show", false);
			expect(
				pref["display.favicon.show"]
			).to.be.false;
			pref.setValue("display.favicon.show", true);
			expect(
				pref["display.favicon.show"]
			).to.be.true;
		});

		it("set string", function () {
			pref.setValue("dns.nameserver", "foo");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("foo");
			pref.setValue("dns.nameserver", "bar");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("bar");
		});

		it("set number", function () {
			expect(
				pref["error.algorithm.rsa.weakKeyLength.treatAs"]
			).to.be.equal(2);
			pref.setValue("error.algorithm.rsa.weakKeyLength.treatAs", 3);
			expect(
				pref["error.algorithm.rsa.weakKeyLength.treatAs"]
			).to.be.equal(3);
			pref.setValue("error.algorithm.rsa.weakKeyLength.treatAs", 1);
			expect(
				pref["error.algorithm.rsa.weakKeyLength.treatAs"]
			).to.be.equal(1);
		});

		it("set bool", function () {
			expect(
				pref["display.favicon.show"]
			).to.be.true;
			pref.setValue("display.favicon.show", false);
			expect(
				pref["display.favicon.show"]
			).to.be.false;
			pref.setValue("display.favicon.show", true);
			expect(
				pref["display.favicon.show"]
			).to.be.true;
		});

		it("getValue after setting", function () {
			expect(
				pref.getValue("display.favicon.show")
			).to.be.true;
			pref.setValue("display.favicon.show", false);
			expect(
				pref.getValue("display.favicon.show")
			).to.be.false;
			pref.setValue("display.favicon.show", true);
			expect(
				pref.getValue("display.favicon.show")
			).to.be.true;
		});

		it("throw if not exist", async function () {
			let res = pref.setValue("policy.xxx", 1);
			await expectAsyncError(res);

			res = pref.setValue("policy.xxx.yyy", true);
			await expectAsyncError(res);

			res = pref.setValue("policy.signRules", "foo");
			await expectAsyncError(res);

			res = pref.setValue("policy.signRules.xxx", 2);
			await expectAsyncError(res);

			res = pref.setValue("policy.signRules", false);
			await expectAsyncError(res);
		});

		it("throw if unexpected type", function () {
			expect(
				() => pref.setValue("dns.nameserver", 1)
			).to;
			expect(
				() => pref.setValue("dns.nameserver", true)
			).to;
			expect(
				() => pref.setValue("error.algorithm.rsa.weakKeyLength.treatAs", "foo")
			).to;
			expect(
				() => pref.setValue("error.algorithm.rsa.weakKeyLength.treatAs", true)
			).to;
			expect(
				() => pref.setValue("display.favicon.show", "foo")
			).to;
			expect(
				() => pref.setValue("display.favicon.show", 2)
			).to;
		});
	});

	describe("storage", function () {
		afterEach(function () {
			sinon.restore();
		});

		it("store and load prefs to/from storage", async function () {
			const storageLocalGet = sinon.spy(fakeBrowser.storage.local, "get");
			const storageLocalSet = sinon.spy(fakeBrowser.storage.local, "set");

			pref.setValue("dns.nameserver", "fooBar");
			expect(
				storageLocalSet.calledOnceWithExactly({ "dns.nameserver": "fooBar" })
			).to.be.true;
			const loadedPref = new StorageLocalPreferences();
			await loadedPref.init();
			expect(
				storageLocalGet.callCount
			).to.be.equal(1);
			expect(
				loadedPref["dns.nameserver"]
			).to.be.equal("fooBar");
		});

		it("clear storage", async function () {
			const storageLocalClear = sinon.spy(fakeBrowser.storage.local, "clear");

			pref.setValue("dns.nameserver", "fooBar");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("fooBar");

			// clearing prefs
			await pref.clear();
			expect(storageLocalClear.calledOnce).to.be.true;
			const storage = await browser.storage.local.get();
			for (const dataStorageScope of StorageLocalPreferences.dataStorageScopes) {
				delete storage[dataStorageScope];
			}
			expect(storage).to.deep.equal({});
			expect(
				pref["dns.nameserver"]
			).to.be.equal("8.8.8.8");

			// loading new prefs after clear should have defaults again
			const loadedPref = new StorageLocalPreferences();
			await loadedPref.init();
			expect(
				loadedPref["dns.nameserver"]
			).to.be.equal("8.8.8.8");
		});

		it("pref should change on storage update", async function () {
			const pref2 = new StorageLocalPreferences();
			await pref2.init();
			// setting option on global pref object
			await pref.setValue("dns.nameserver", "fooBar");
			// should sync it to local pref object
			expect(
				pref2["dns.nameserver"]
			).to.be.equal("fooBar");

			// setting option on local pref object
			await pref2.setValue("dns.nameserver", "muh");
			// should sync it to global pref object
			expect(
				pref["dns.nameserver"]
			).to.be.equal("muh");
		});

		it("other storage changes are ignored", function () {
			pref.setValue("dns.nameserver", "fooBar");
			fakeBrowser.storage.onChanged.addListener.yield({
				"dns.nameserver": {
					// @ts-expect-error
					oldValue: pref._prefs,
					newValue: "sync",
				}
			}, "sync");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("fooBar");
		});

		it("test multiple pref changes at the same time", async function () {
			const pref2 = new StorageLocalPreferences();
			await pref2.init();

			const addListener = fakeBrowser.storage.onChanged.addListener;
			sinon.replace(fakeBrowser.storage.onChanged, "addListener", sinon.stub());

			/** @type {{[x: string]: any}[]} */
			const storageCalls = [];
			browser.storage.onChanged.addListener(x => storageCalls.push(JSON.parse(JSON.stringify(x))));
			/**
			 * @returns {void}
			 */
			function triggerListener() {
				const items = storageCalls.shift();
				if (!items) {
					return;
				}
				addListener.yield(items, "local");
			}

			await pref.setValue("dns.nameserver", "fooBar");
			await pref.setValue("arh.read", true);
			triggerListener();
			await pref.setValue("color.nosig.background", "red");
			await pref.setValue("dns.proxy.port", 1111);

			while (storageCalls.length) {
				triggerListener();
			}

			expect(pref["dns.nameserver"]).to.be.equal("fooBar");
			expect(pref2["dns.nameserver"]).to.be.equal("fooBar");
			expect(pref["arh.read"]).to.be.equal(true);
			expect(pref2["arh.read"]).to.be.equal(true);
			expect(pref["color.nosig.background"]).to.be.equal("red");
			expect(pref2["color.nosig.background"]).to.be.equal("red");
			expect(pref["dns.proxy.port"]).to.be.equal(1111);
			expect(pref2["dns.proxy.port"]).to.be.equal(1111);
		});

		it("safeGetLocalStorage - retry on reject", async function () {
			pref.setValue("dns.nameserver", "fooBar");

			const storageLocalGet = sinon.stub(fakeBrowser.storage.local, "get");
			storageLocalGet.callThrough();
			storageLocalGet.onFirstCall().rejects("a failure");
			storageLocalGet.onSecondCall().rejects("a failure");

			const loadedPref = new StorageLocalPreferences();
			await loadedPref.init();
			expect(storageLocalGet.calledThrice).to.be.true;
			expect(
				loadedPref["dns.nameserver"]
			).to.be.equal("fooBar");
		});

		// eslint-disable-next-line mocha/no-skipped-tests
		xit("safeGetLocalStorage - single timeout", async function () {
			// eslint-disable-next-line no-invalid-this
			this.timeout(5000);

			const storageLocalGet = sinon.stub(fakeBrowser.storage.local, "get");
			storageLocalGet.callThrough();

			pref.setValue("dns.nameserver", "fooBar");

			storageLocalGet.onFirstCall().callsFake(async items => {
				await new Promise(resolve => { setTimeout(resolve, 4000); });
				// eslint-disable-next-line no-invalid-this
				return this.wrappedMethod(items);
			});

			const loadedPref = new StorageLocalPreferences();
			await loadedPref.init();
			expect(storageLocalGet.calledTwice).to.be.true;
			expect(
				loadedPref["dns.nameserver"]
			).to.be.equal("fooBar");
		});

		// eslint-disable-next-line mocha/no-skipped-tests
		xit("safeGetLocalStorage - complete timeout", async function () {
			// eslint-disable-next-line no-invalid-this
			this.timeout(20000);

			const storageLocalGet = sinon.stub(fakeBrowser.storage.local, "get");

			pref.setValue("dns.nameserver", "fooBar");

			storageLocalGet.callsFake(async items => {
				await new Promise(resolve => { setTimeout(resolve, 4000); });
				// eslint-disable-next-line no-invalid-this
				return this.wrappedMethod(items);
			});
			storageLocalGet.onSecondCall().rejects("a failure");

			const loadedPref = new StorageLocalPreferences();
			let timedOut = true;
			try {
				await loadedPref.init();
				timedOut = false;
			} catch {
				// expected
			}
			expect(timedOut).to.be.true;
			expect(storageLocalGet.callCount).to.be.greaterThan(2);
			expect(() =>
				loadedPref["dns.nameserver"]
			).to.throw();
		});
	});

	describe("Managed storage", function () {
		afterEach(async function () {
			await fakeBrowser.storage.managed.clear();
			// @ts-expect-error
			pref._isInitializedDeferred = null;
			await pref.init();
			sinon.restore();
		});

		it("Managed bool option", async function () {
			expect(pref["arh.read"]).to.be.equal(false);

			await fakeBrowser.storage.managed.set({ "arh.read": true });
			expect(pref["arh.read"]).to.be.equal(true);
			await fakeBrowser.storage.managed.set({ "arh.read": false });
			expect(pref["arh.read"]).to.be.equal(false);

			// On e.g. macOS boolean options will be represented as integer
			await fakeBrowser.storage.managed.set({ "arh.read": 1 });
			expect(pref["arh.read"]).to.be.equal(true);
			await fakeBrowser.storage.managed.set({ "arh.read": 0 });
			expect(pref["arh.read"]).to.be.equal(false);
			// We will only accept 0 and 1
			await fakeBrowser.storage.managed.set({ "arh.read": 2 });
			expect(() => pref["arh.read"]).to.throw();
		});

		it("Managed default set that gets overwritten", async function () {
			await fakeBrowser.storage.managed.set({ "dns.nameserver": "1.2.3.4" });
			const pref2 = new StorageLocalPreferences();
			await pref2.init();

			expect(pref["dns.nameserver"]).to.be.equal("1.2.3.4");
			expect(pref2["dns.nameserver"]).to.be.equal("1.2.3.4");

			pref.setValue("dns.nameserver", "fooBar");
			expect(pref["dns.nameserver"]).to.be.equal("fooBar");
			expect(pref2["dns.nameserver"]).to.be.equal("fooBar");

			await pref.clear();
			await pref2.clear();
			expect(pref["dns.nameserver"]).to.be.equal("1.2.3.4");
			expect(pref2["dns.nameserver"]).to.be.equal("1.2.3.4");
		});

		it("Managed pref gets updated", async function () {
			expect(pref["dns.nameserver"]).to.be.equal("8.8.8.8");

			await fakeBrowser.storage.managed.set({ "dns.nameserver": "1.2.3.4" });
			expect(pref["dns.nameserver"]).to.be.equal("1.2.3.4");

			await fakeBrowser.storage.managed.set({ "dns.nameserver": "1.1.1.1" });
			expect(pref["dns.nameserver"]).to.be.equal("1.1.1.1");
		});

		it("Managed storage not available", async function () {
			const storageManagedGet = sinon.stub(fakeBrowser.storage.managed, "get");
			storageManagedGet.rejects(new Error("Managed storage manifest not found"));

			const loadedPref = new StorageLocalPreferences();
			await loadedPref.init();
			expect(storageManagedGet.calledOnce).to.be.true;
			expect(loadedPref["dns.nameserver"]).to.be.equal("8.8.8.8");
		});
	});

	describe("account settings", function () {
		it("default value", function () {
			expect(pref["account.dkim.enable"]("fooAccount")).to.be.equal(true);
			expect(pref["account.arh.read"]("barAccount")).to.be.equal(false);
			expect(pref["account.arh.allowedAuthserv"]("fooAccount")).to.be.equal("");
			expect(pref["account.arh.read"](undefined)).to.be.equal(false);

			pref.setValue("dkim.enable", false);
			pref.setValue("arh.read", true);
			expect(pref["account.dkim.enable"]("fooAccount")).to.be.equal(false);
			expect(pref["account.arh.read"]("barAccount")).to.be.equal(true);
			expect(pref["account.arh.read"](undefined)).to.be.equal(true);
		});

		it("account specific setting", function () {
			pref.setAccountValue("dkim.enable", "fooAccount", 2);
			pref.setAccountValue("arh.allowedAuthserv", "fooAccount", "foo.com");
			pref.setAccountValue("arh.read", "fooAccount", 1);
			pref.setAccountValue("arh.read", "barAccount", 2);

			expect(pref.getAccountValue("dkim.enable", "fooAccount")).to.be.equal(2);
			expect(pref.getAccountValue("dkim.enable", "barAccount")).to.be.equal(0);
			expect(pref.getAccountValue("arh.read", "fooAccount")).to.be.equal(1);
			expect(pref.getAccountValue("arh.read", "barAccount")).to.be.equal(2);

			expect(pref["account.dkim.enable"]("fooAccount")).to.be.equal(false);
			expect(pref["account.dkim.enable"]("barAccount")).to.be.equal(true);
			expect(pref["account.arh.allowedAuthserv"]("fooAccount")).to.be.equal("foo.com");
			expect(pref["account.arh.allowedAuthserv"]("barAccount")).to.be.equal("");
			expect(pref["account.arh.read"]("fooAccount")).to.be.equal(true);
			expect(pref["account.arh.read"]("barAccount")).to.be.equal(false);
		});
	});
});
