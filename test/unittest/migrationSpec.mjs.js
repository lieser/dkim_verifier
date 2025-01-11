/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */

import { migrateKeyStore, migratePrefs, migrateSignRulesUser } from "../../modules/migration.mjs.js";
import { KeyDb } from "../../modules/dkim/keyStore.mjs.js";
import SignRules from "../../modules/dkim/signRules.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import sinon from "../helpers/sinonUtils.mjs.js";

describe("migration [unittest]", function () {
	describe("migration of preferences", function () {
		before(function () {
			if (!hasWebExtensions) {
				// eslint-disable-next-line no-invalid-this
				this.skip();
			}
		});

		beforeEach(async function () {
			await prefs.clear();
		});

		it("normal migration", async function () {
			browser.migration = {
				getUserPrefs: sinon.fake.resolves({
					"arh.read": true,
					"dkim.enable": false,
					"dns.nameserver": "1.1.1.1",
					"dns.proxy.port": "42",
					"error.policy.wrong_sdid.asWarning": true,
					"key.storing": 2,
					"policy.signRules.autoAddRule": true,
					"saveResult": true,
				}),
				getAccountPrefs: sinon.fake.resolves({
					account1: {
						"dkim.enable": 0,
						"arh.read": 2,
						"arh.allowedAuthserv": "foo.com",
					},
					account3: {
						"dkim.enable": 1,
					},
				}),
				getDkimKeys: sinon.fake.rejects("not available"),
				getSignRulesUser: sinon.fake.rejects("not available"),
			};
			await migratePrefs();
			expect(prefs["arh.read"]).to.be.equal(true);
			expect(prefs["dkim.enable"]).to.be.equal(false);
			expect(prefs["dns.nameserver"]).to.be.equal("1.1.1.1");
			expect(prefs["key.storing"]).to.be.equal(2);
			expect(prefs.saveResult).to.be.equal(true);
			// renamed
			expect(prefs["policy.signRules.autoAddRule.enable"]).to.be.equal(true);
			expect(prefs["policy.signRules.error.wrong_sdid.asWarning"]).to.be.equal(true);
			// type changed
			expect(prefs["dns.proxy.port"]).to.be.equal(42);

			expect(prefs["account.dkim.enable"]("account1")).to.be.equal(false);
			expect(prefs["account.arh.read"]("account1")).to.be.equal(false);
			expect(prefs["account.arh.allowedAuthserv"]("account1")).to.be.equal("foo.com");
			expect(prefs["account.dkim.enable"]("account3")).to.be.equal(true);
			expect(prefs["account.arh.read"]("account3")).to.be.equal(true);
			expect(prefs["account.arh.allowedAuthserv"]("account3")).to.be.equal("");
		});
		it("errors should be ignored", async function () {
			browser.migration = {
				getUserPrefs: sinon.fake.resolves({
					"arh.read": true,
					"dkim.enable": "this should be a boolean",
					"dns.nameserver": "1.1.1.1",
					"this.pref.does.not.exist": "foo",
					"key.storing": 2,
				}),
				getDkimKeys: sinon.fake.rejects("not available"),
				getAccountPrefs: sinon.fake.resolves({
					account1: {
						"dkim.enable": true,
						"arh.read": false,
						"arh.allowedAuthserv": 1,
					},
					account3: {
						"dkim.enable": 2,
					},
				}),
				getSignRulesUser: sinon.fake.rejects("not available"),
			};
			await migratePrefs();
			expect(prefs["arh.read"]).to.be.equal(true);
			expect(prefs["dns.nameserver"]).to.be.equal("1.1.1.1");
			expect(prefs["key.storing"]).to.be.equal(2);
			// prefs with wrong type should have default value
			expect(prefs["dkim.enable"]).to.be.equal(true);

			expect(prefs["account.dkim.enable"]("account1")).to.be.equal(true);
			expect(prefs["account.arh.read"]("account1")).to.be.equal(true);
			expect(prefs["account.arh.allowedAuthserv"]("account1")).to.be.equal("");
			expect(prefs["account.dkim.enable"]("account3")).to.be.equal(false);
		});
		it("skip migration if preferences already exist", async function () {
			browser.migration = {
				getUserPrefs: sinon.fake.resolves({
					"arh.read": true,
				}),
				getAccountPrefs: sinon.fake.resolves({
					account1: {
						"arh.allowedAuthserv": "foo.com",
					},
				}),
				getDkimKeys: sinon.fake.rejects("not available"),
				getSignRulesUser: sinon.fake.rejects("not available"),
			};
			await prefs.setValue("dkim.enable", true);
			await migratePrefs();
			expect(prefs["arh.read"]).to.be.equal(false);
			expect(prefs["account.arh.allowedAuthserv"]("account1")).to.be.equal("");
		});
		it("don't skip migration if only sign rules exist", async function () {
			browser.migration = {
				getUserPrefs: sinon.fake.resolves({
					"arh.read": true,
				}),
				getAccountPrefs: sinon.fake.resolves({
					account1: {
						"arh.allowedAuthserv": "foo.com",
					},
				}),
				getDkimKeys: sinon.fake.rejects("not available"),
				getSignRulesUser: sinon.fake.rejects("not available"),
			};
			await SignRules.addException("foo@bar.com");
			await migratePrefs();
			expect(prefs["arh.read"]).to.be.equal(true);
			expect(prefs["account.arh.allowedAuthserv"]("account1")).to.be.equal("foo.com");
		});
	});

	describe("migration of keys", function () {
		before(function () {
			if (!hasWebExtensions) {
				// eslint-disable-next-line no-invalid-this
				this.skip();
			}
		});

		beforeEach(async function () {
			await KeyDb.clear();

			browser.migration = {
				getUserPrefs: sinon.fake.rejects("not available"),
				getAccountPrefs: sinon.fake.rejects("not available"),
				getDkimKeys: sinon.fake.resolves({
					maxId: 1,
					keys: [
						{
							id: 1,
							sdid: "foo.com",
							selector: "selector",
							key: "key",
							insertedAt: "2021-02-03",
							lastUsedAt: "2021-02-03",
							secure: false,
						},
					],
				}),
				getSignRulesUser: sinon.fake.rejects("not available"),
			};
		});

		it("normal migration of keys", async function () {
			await migrateKeyStore();

			const res = await KeyDb.fetch("foo.com", "selector");
			expect(res?.key).is.equal("key");
		});
		it("skip migration if keys already exist", async function () {
			await KeyDb.store("bar.com", "selector", "key2", false);
			await migrateKeyStore();

			const res = await KeyDb.fetch("foo.com", "selector");
			expect(res).is.null;
		});
		it("don't skip migration of keys if only preferences exist", async function () {
			await prefs.setValue("dkim.enable", true);
			await migrateKeyStore();

			const res = await KeyDb.fetch("foo.com", "selector");
			expect(res?.key).is.equal("key");
		});
	});

	describe("migration of sign rules", function () {
		before(function () {
			if (!hasWebExtensions) {
				// eslint-disable-next-line no-invalid-this
				this.skip();
			}
		});

		beforeEach(async function () {
			await SignRules.clearRules();

			browser.migration = {
				getUserPrefs: sinon.fake.rejects("not available"),
				getAccountPrefs: sinon.fake.rejects("not available"),
				getDkimKeys: sinon.fake.rejects("not available"),
				getSignRulesUser: sinon.fake.resolves({
					maxId: 1,
					rules: [
						{
							id: 1,
							domain: "foo.com",
							listId: "",
							addr: "*",
							sdid: "foo.com",
							type: SignRules.TYPE.ALL,
							priority: SignRules.PRIORITY.USERINSERT_RULE_ALL,
							enabled: true,
						},
					],
				}),
			};
		});

		const dkimNone = {
			version: "1.1",
			result: "none",
			warnings: []
		};

		it("normal migration of sign rules", async function () {
			await migrateSignRulesUser();

			const res = await SignRules.check(dkimNone, "bar@foo.com");
			expect(res.result).is.equal("PERMFAIL");
		});
		it("skip migration if sign rules already exist", async function () {
			await SignRules.addRule("bar.com", null, "*", "bar.com", SignRules.TYPE.ALL);
			await migrateSignRulesUser();

			const res = await SignRules.check(dkimNone, "bar@foo.com");
			expect(res.result).is.equal("none");
		});
		it("don't skip migration of sign rules if only preferences exist", async function () {
			await prefs.setValue("dkim.enable", true);
			await migrateSignRulesUser();

			const res = await SignRules.check(dkimNone, "bar@foo.com");
			expect(res.result).is.equal("PERMFAIL");
		});
	});
});
