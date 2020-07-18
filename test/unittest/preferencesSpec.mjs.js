/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../WebExtensions.d.ts" />
/* eslint-env webextensions */

import { fakeBrowser, hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import prefs, { ObjPreferences, StorageLocalPreferences } from "../../modules/preferences.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";

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
			).to.throw;
			expect(
				() => pref.getValue("policy.xxx.yyy")
			).to.throw;
			expect(
				() => pref.getValue("policy.signRules")
			).to.throw;
			expect(
				() => pref.getValue("policy.signRules.xxx")
			).to.throw;
			expect(
				() => pref.getValue("policy.signRules")
			).to.throw;
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
			).to.throw;
			expect(
				() => pref.getNumber("policy.xxx.yyy")
			).to.throw;
			expect(
				() => pref.getString("policy.signRules")
			).to.throw;
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
		it("throw if not exist", function () {
			expect(
				// @ts-ignore
				() => pref["policy.xxx"]
			).to.throw;
			expect(
				// @ts-ignore
				() => pref["policy.xxx.yyy"]
			).to.throw;
			expect(
				// @ts-ignore
				() => pref["policy.signRules"]
			).to.throw;
			expect(
				// @ts-ignore
				() => pref["policy.signRules.xxx"]
			).to.throw;
			expect(
				// @ts-ignore
				() => pref["policy.signRules"]
			).to.throw;
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
		it("throw if not exist", function () {
			expect(
				() => pref.setValue("policy.xxx", 1)
			).to.throw;
			expect(
				() => pref.setValue("policy.xxx.yyy", true)
			).to.throw;
			expect(
				() => pref.setValue("policy.signRules", "foo")
			).to.throw;
			expect(
				() => pref.setValue("policy.signRules.xxx", 2)
			).to.throw;
			expect(
				() => pref.setValue("policy.signRules", false)
			).to.throw;
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
			pref.clear();
			expect(fakeBrowser.storage.local.clear.calledOnce).to.be.true;
			const storage = await browser.storage.local.get();
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
			after(function () {
				fakeBrowser.storage.local.set.callsFake(fakeBrowser.storage.local._set);
			});

			fakeBrowser.storage.local.set.callsFake(async items => {
				await fakeBrowser.storage.local._set(items, undefined);

				/** @type {Object.<string, {oldValue: any, newValue: any}>} */
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
		});
		it("other storage changes are ignored", function () {
			pref.setValue("dns.nameserver", "fooBar");
			fakeBrowser.storage.onChanged.addListener.yield({
				"dns.nameserver": {
					oldValue: pref._prefs,
					newValue: "sync",
				}
			}, "sync");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("fooBar");
		});
		it("test multiple pref changes at the same time", async function () {
			after(function () {
				fakeBrowser.storage.local.set.callsFake(fakeBrowser.storage.local._set);
			});

			/** @type {Object.<string, any>[]} */
			const storageCalls = [];
			fakeBrowser.storage.local.set.callsFake(items => {
				storageCalls.push(JSON.parse(JSON.stringify(items)));
				return fakeBrowser.storage.local._set(items, undefined);
			});

			function triggerListener() {
				const items = storageCalls.shift();
				if (!items) {
					return;
				}
				/** @type {Object.<string, {oldValue: any, newValue: any}>} */
				const changes = {};
				for (const [name, value] of Object.entries(items)) {
					changes[name] = {
						oldValue: {},
						newValue: value,
					};
				}
				fakeBrowser.storage.onChanged.addListener.yield(changes, "local");
			}

			await pref.setValue("dns.nameserver", "fooBar");
			await pref.setValue("arh.read", true);
			triggerListener();
			await pref.setValue("color.nosig.background", "red");
			await pref.setValue("dns.proxy.port", 1111);

			while (storageCalls.length > 0) {
				triggerListener();
			}

			expect(pref["dns.nameserver"]).to.be.equal("fooBar");
			expect(pref["arh.read"]).to.be.equal(true);
			expect(pref["color.nosig.background"]).to.be.equal("red");
			expect(pref["dns.proxy.port"]).to.be.equal(1111);
		});
	});
	describe("account settings", function () {
		it("default value", function () {
			expect(pref["account.dkim.enable"]("fooAccount")).to.be.equal(true);
			expect(pref["account.arh.read"]("barAccount")).to.be.equal(false);
			expect(pref["account.arh.allowedAuthserv"]("fooAccount")).to.be.equal("");

			pref.setValue("dkim.enable", false);
			pref.setValue("arh.read", true);
			expect(pref["account.dkim.enable"]("fooAccount")).to.be.equal(false);
			expect(pref["account.arh.read"]("barAccount")).to.be.equal(true);
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
