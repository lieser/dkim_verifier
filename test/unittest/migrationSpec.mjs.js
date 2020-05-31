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

import expect from "../helpers/chaiUtils.mjs.js";
import { hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import { migratePrefs } from "../../modules/migration.mjs.js";
import prefs from "../../modules/preferences.mjs.js";

// @ts-ignore
import sinonImport from "../../node_modules/sinon/pkg/sinon-esm.js";
/** @type {import("sinon")} */
// @ts-ignore
const sinon = sinonImport;

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
					"saveResult": true,
				}),
			};
			await migratePrefs();
			expect(prefs["arh.read"]).to.be.equal(true);
			expect(prefs["dkim.enable"]).to.be.equal(false);
			expect(prefs["dns.nameserver"]).to.be.equal("1.1.1.1");
			expect(prefs["key.storing"]).to.be.equal(2);
			expect(prefs.saveResult).to.be.equal(true);
			// renamed
			expect(prefs["policy.signRules.error.wrong_sdid.asWarning"]).to.be.equal(true);
			// type changed
			expect(prefs["dns.proxy.port"]).to.be.equal(42);
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
			};
			await migratePrefs();
			expect(prefs["arh.read"]).to.be.equal(true);
			expect(prefs["dns.nameserver"]).to.be.equal("1.1.1.1");
			expect(prefs["key.storing"]).to.be.equal(2);
			// prefs with wrong type should have default value
			expect(prefs["dkim.enable"]).to.be.equal(true);
		});
		it("skip migration if preferences already exist", async function () {
			browser.migration = {
				getUserPrefs: sinon.fake.resolves({
					"arh.read": true,
				}),
			};
			await prefs.setValue("dkim.enable", true);
			await migratePrefs();
			expect(prefs["arh.read"]).to.be.equal(false);
		});
	});
});
