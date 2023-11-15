/**
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./migration.d.ts" />
///<reference path="./mozilla.d.ts" />
/* global ExtensionCommon, Services */

"use strict";

// eslint-disable-next-line no-var
var { Sqlite } = ChromeUtils.import("resource://gre/modules/Sqlite.jsm");
// @ts-expect-error
// eslint-disable-next-line no-var
var OS;
if (typeof PathUtils === "undefined") {
	// TB < 115
	({ OS } = ChromeUtils.import("resource://gre/modules/osfile.jsm"));
}
// @ts-expect-error
// eslint-disable-next-line no-var
var { FileUtils } = ChromeUtils.import("resource://gre/modules/FileUtils.jsm");

this.migration = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * Returns the preferences set in a preference branch.
	 *
	 * @param {nsIPrefBranch} prefBranch
	 * @returns {{[prefName: string]: boolean|number|string}}
	 */
	#getChildPrefs(prefBranch) {
		const setPrefNames = prefBranch.getChildList("");
		/** @type {{[prefName: string]: boolean|number|string}} */
		const childPrefs = {};
		for (const prefName of setPrefNames) {
			prefBranch.getPrefType(prefName);
			switch (prefBranch.getPrefType(prefName)) {
				case prefBranch.PREF_BOOL:
					childPrefs[prefName] = prefBranch.getBoolPref(prefName);
					break;
				case prefBranch.PREF_INT:
					childPrefs[prefName] = prefBranch.getIntPref(prefName);
					break;
				case prefBranch.PREF_STRING:
					childPrefs[prefName] = prefBranch.getCharPref(prefName);
					break;
				default:
					console.warn(`Preference ${prefName} has unexpected type ${prefBranch.getPrefType(prefName)}`);
			}
		}
		return childPrefs;
	}

	/**
	 * Open connection to an SQLite database if it exist.
	 *
	 * @param {string} fileName
	 * @returns {Promise<any>?}
	 */
	#openSqlite(fileName) {
		// Retains absolute paths and normalizes relative as relative to profile.
		let path;
		if (OS) {
			path = OS.Path.join(OS.Constants.Path.profileDir, fileName);
		} else {
			path = PathUtils.join(PathUtils.profileDir, fileName);
		}
		const file = FileUtils.File(path);

		// test that db exists
		if (!file.exists()) {
			return null;
		}

		return Sqlite.openConnection({ path: fileName });

	}

	/**
	 * @param {ExtensionCommon.Context} _context
	 * @returns {{migration: browser.migration}}
	 */
	getAPI(_context) {
		return {
			migration: {
				getUserPrefs: () => {
					const dkimPrefs = Services.prefs.getBranch("extensions.dkim_verifier.");
					return Promise.resolve(this.#getChildPrefs(dkimPrefs));
				},
				getAccountPrefs: () => {
					const mailPrefs = Services.prefs.getBranch("mail.");
					const accounts = mailPrefs.getCharPref("accountmanager.accounts").split(",");
					/** @type {{[account: string]: {[prefName: string]: boolean|number|string}}} */
					const accountPrefs = {};
					for (const account of accounts) {
						const server = mailPrefs.getCharPref(`account.${account}.server`);
						const dkimAccountPrefs = Services.prefs.getBranch(`mail.server.${server}.dkim_verifier.`);
						const prefs = this.#getChildPrefs(dkimAccountPrefs);
						if (Object.keys(prefs).length) {
							accountPrefs[account] = prefs;
						}
					}
					return Promise.resolve(accountPrefs);
				},
				getDkimKeys: async () => {
					const conn = await this.#openSqlite("dkimKey.sqlite");
					if (!conn) {
						return null;
					}

					const sqlRes = await conn.execute("SELECT * FROM keys");
					await conn.close();

					let maxId = 0;
					/** @type {import("../modules/dkim/keyStore.mjs.js").StoredDkimKey[]} */
					const keys = [];
					for (const key of sqlRes) {
						keys.push({
							id: ++maxId,
							sdid: key.getResultByName("SDID"),
							selector: key.getResultByName("selector"),
							key: key.getResultByName("key"),
							insertedAt: key.getResultByName("insertedAt"),
							lastUsedAt: key.getResultByName("lastUsedAt"),
							secure: key.getResultByName("secure") === 1,
						});
					}
					return { maxId, keys };
				},
				getSignRulesUser: async () => {
					const conn = await this.#openSqlite("dkimPolicy.sqlite");
					if (!conn) {
						return null;
					}

					const sqlRes = await conn.execute("SELECT * FROM signers");
					await conn.close();

					let maxId = 0;
					/** @type {import("../modules/dkim/signRules.mjs.js").DkimSignRuleUser[]} */
					const userRules = [];
					for (const rule of sqlRes) {
						userRules.push({
							id: ++maxId,
							domain: rule.getResultByName("domain") ?? "",
							listId: rule.getResultByName("listID") ?? "",
							addr: rule.getResultByName("addr"),
							sdid: rule.getResultByName("sdid") ?? "",
							type: rule.getResultByName("ruletype"),
							priority: rule.getResultByName("priority"),
							enabled: rule.getResultByName("enabled") === 1,
						});
					}
					return { maxId, rules: userRules };
				}
			},
		};
	}
};
