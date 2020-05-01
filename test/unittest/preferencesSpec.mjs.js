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
					{ preferences: { "dns.nameserver": "fooBar" } })
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
			await browser.storage.local.set({ someStorage: "this should not be cleared by prefs" });

			pref.setValue("dns.nameserver", "fooBar");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("fooBar");

			// clearing prefs should not affect other storage
			pref.clear();
			expect(
				fakeBrowser.storage.local.set.lastCall.calledWithExactly(
					{ preferences: {} })
			).to.be.true;
			expect(
				pref["dns.nameserver"]
			).to.be.equal("8.8.8.8");
			expect(
				(await browser.storage.local.get("someStorage")).someStorage
			).to.be.equal("this should not be cleared by prefs");

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
			pref.setValue("dns.nameserver", "fooBar");
			fakeBrowser.storage.onChanged.addListener.yield({
				preferences: {
					oldValue: pref2._prefs,
					newValue: pref._prefs,
				}
			}, "local");
			// should sync it to local pref object
			expect(
				pref2["dns.nameserver"]
			).to.be.equal("fooBar");

			// setting option on local pref object
			pref2.setValue("dns.nameserver", "muh");
			fakeBrowser.storage.onChanged.addListener.yield({
				preferences: {
					oldValue: pref._prefs,
					newValue: pref2._prefs,
				}
			}, "local");
			// should sync it to global pref object
			expect(
				pref["dns.nameserver"]
			).to.be.equal("muh");
		});
		it("other storage changes are ignored", function () {
			pref.setValue("dns.nameserver", "fooBar");
			fakeBrowser.storage.onChanged.addListener.yield({
				preferences: {
					oldValue: pref._prefs,
					newValue: {},
				}
			}, "sync");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("fooBar");
			fakeBrowser.storage.onChanged.addListener.yield({
				preferencesX: {
					oldValue: pref._prefs,
					newValue: {},
				}
			}, "local");
			expect(
				pref["dns.nameserver"]
			).to.be.equal("fooBar");
		});
	});
});
