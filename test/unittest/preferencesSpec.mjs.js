/**
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env shared-node-browser, webextensions */

import expect, { expectAsyncError } from "../helpers/chaiUtils.mjs.js";
import { fakeBrowser, hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import prefs, { ObjPreferences, StorageLocalPreferences } from "../../modules/preferences.mjs.js";

describe("preferences [unittest]", function () {
	/** @type {import("../../modules/preferences.mjs.js").BasePreferences} */
	let pref;

	before(async function () {
		pref = hasWebExtensions ? prefs : new ObjPreferences();
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
			).to;
			expect(
				() => pref.getNumber("dns.proxy.type")
			).to;
			expect(
				() => pref.getBool("error.algorithm.rsa.weakKeyLength.treatAs")
			).to;
			expect(
				() => pref.getString("error.algorithm.rsa.weakKeyLength.treatAs")
			).to;
			expect(
				() => pref.getNumber("display.favicon.show")
			).to;
			expect(
				() => pref.getString("display.favicon.show")
			).to;
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
		before(function () {
			if (!hasWebExtensions) {
				// eslint-disable-next-line no-invalid-this
				this.skip();
			}
		});

		beforeEach(function () {
			fakeBrowser.storage.local.clear.resetHistory();
			fakeBrowser.storage.local.get.resetHistory();
			fakeBrowser.storage.local.set.resetHistory();
		});

		it("store and load prefs to/from storage", async function () {
			pref.setValue("dns.nameserver", "fooBar");
			expect(
				fakeBrowser.storage.local.set.calledOnceWithExactly(
					{ "dns.nameserver": "fooBar" })
			).to.be.true;
			const loadedPref = new StorageLocalPreferences();
			await loadedPref.init();
			expect(
				fakeBrowser.storage.local.get.callCount
			).to.be.equal(1);
			expect(
				loadedPref["dns.nameserver"]
			).to.be.equal("fooBar");
		});
		it("clear storage", async function () {
			pref.setValue("dns.nameserver", "fooBar");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("fooBar");

			// clearing prefs
			await pref.clear();
			expect(fakeBrowser.storage.local.clear.calledOnce).to.be.true;
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
			try {
				fakeBrowser.storage.local.set.callsFake(async items => {
					await fakeBrowser.storage.local._set(items, undefined);

					/** @type {{[prefName: string]: {oldValue: any, newValue: any}}} */
					const changes = {};
					for (const [name, value] of Object.entries(items)) {
						changes[name] = {
							oldValue: {},
							newValue: JSON.parse(JSON.stringify(value)),
						};
					}
					fakeBrowser.storage.onChanged.addListener.yield(changes, "local");
				});

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

			} finally {
				fakeBrowser.storage.local.set.callsFake(fakeBrowser.storage.local._set);
			}
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
			/** @type {{[x: string]: any}[]} */
			const storageCalls = [];
			/**
			 * @returns {void}
			 */
			function triggerListener() {
				const items = storageCalls.shift();
				if (!items) {
					return;
				}
				/** @type {{[prefName: string]: {oldValue: any, newValue: any}}} */
				const changes = {};
				for (const [name, value] of Object.entries(items)) {
					changes[name] = {
						oldValue: {},
						newValue: value,
					};
				}
				fakeBrowser.storage.onChanged.addListener.yield(changes, "local");
			}

			try {
				fakeBrowser.storage.local.set.callsFake(items => {
					storageCalls.push(JSON.parse(JSON.stringify(items)));
					return fakeBrowser.storage.local._set(items, undefined);
				});

				await pref.setValue("dns.nameserver", "fooBar");
				await pref.setValue("arh.read", true);
				triggerListener();
				await pref.setValue("color.nosig.background", "red");
				await pref.setValue("dns.proxy.port", 1111);

				while (storageCalls.length) {
					triggerListener();
				}

				expect(pref["dns.nameserver"]).to.be.equal("fooBar");
				expect(pref["arh.read"]).to.be.equal(true);
				expect(pref["color.nosig.background"]).to.be.equal("red");
				expect(pref["dns.proxy.port"]).to.be.equal(1111);
			} finally {
				fakeBrowser.storage.local.set.callsFake(fakeBrowser.storage.local._set);
			}
		});
		it("safeGetLocalStorage - retry on reject", async function () {
			try {
				pref.setValue("dns.nameserver", "fooBar");

				fakeBrowser.storage.local.get.onFirstCall().rejects("a failure");
				fakeBrowser.storage.local.get.onSecondCall().rejects("a failure");

				const loadedPref = new StorageLocalPreferences();
				await loadedPref.init();
				expect(fakeBrowser.storage.local.get.calledThrice).to.be.true;
				expect(
					loadedPref["dns.nameserver"]
				).to.be.equal("fooBar");
			} finally {
				fakeBrowser.storage.local.get.resetBehavior();
				fakeBrowser.storage.local.get.callsFake(fakeBrowser.storage.local._get);
			}
		});
		// eslint-disable-next-line mocha/no-skipped-tests
		xit("safeGetLocalStorage - single timeout", async function () {
			// eslint-disable-next-line no-invalid-this
			this.timeout(5000);
			try {
				pref.setValue("dns.nameserver", "fooBar");

				fakeBrowser.storage.local.get.onFirstCall().callsFake(async items => {
					await new Promise(resolve => { setTimeout(resolve, 4000); });
					return fakeBrowser.storage.local._get(items);
				});

				const loadedPref = new StorageLocalPreferences();
				await loadedPref.init();
				expect(fakeBrowser.storage.local.get.calledTwice).to.be.true;
				expect(
					loadedPref["dns.nameserver"]
				).to.be.equal("fooBar");

			} finally {
				fakeBrowser.storage.local.get.resetBehavior();
				fakeBrowser.storage.local.get.callsFake(fakeBrowser.storage.local._get);
			}
		});
		// eslint-disable-next-line mocha/no-skipped-tests
		xit("safeGetLocalStorage - complete timeout", async function () {
			// eslint-disable-next-line no-invalid-this
			this.timeout(20000);
			try {
				pref.setValue("dns.nameserver", "fooBar");

				fakeBrowser.storage.local.get.callsFake(async items => {
					await new Promise(resolve => { setTimeout(resolve, 4000); });
					return fakeBrowser.storage.local._get(items);
				});
				fakeBrowser.storage.local.get.onSecondCall().rejects("a failure");

				const loadedPref = new StorageLocalPreferences();
				let timedOut = true;
				try {
					await loadedPref.init();
					timedOut = false;
				} catch (error) {
					// expected
				}
				expect(timedOut).to.be.true;
				expect(fakeBrowser.storage.local.get.callCount).to.be.greaterThan(2);
				expect(() =>
					loadedPref["dns.nameserver"]
				).to.throw();
			} finally {
				fakeBrowser.storage.local.get.resetBehavior();
				fakeBrowser.storage.local.get.callsFake(fakeBrowser.storage.local._get);
			}
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
