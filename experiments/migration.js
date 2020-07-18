/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./migration.d.ts" />
///<reference path="../mozilla.d.ts" />
/* eslint-env worker */
/* global ChromeUtils, ExtensionCommon */

"use strict";

// @ts-ignore
// eslint-disable-next-line no-var
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");

// eslint-disable-next-line no-invalid-this
this.migration = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * Returns the preferences set in a preference branch.
	 *
	 * @param {nsIPrefBranch} prefBranch
	 * @returns {Object.<string, boolean|number|string>}
	 */
	_getChildPrefs(prefBranch) {
		const setPrefNames = prefBranch.getChildList("");
		/** @type {Object.<string, boolean|number|string>} */
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
	 * @param {ExtensionCommon.Context} context
	 * @returns {{migration: browser.migration}}
	 */
	// eslint-disable-next-line no-unused-vars
	getAPI(context) {
		return {
			migration: {
				getUserPrefs: () => {
					const dkimPrefs = Services.prefs.getBranch("extensions.dkim_verifier.");
					return Promise.resolve(this._getChildPrefs(dkimPrefs));
				},
				getAccountPrefs: () => {
					const mailPrefs = Services.prefs.getBranch("mail.");
					const accounts = mailPrefs.getCharPref("accountmanager.accounts").split(",");
					/** @type {Object.<string, Object.<string, boolean|number|string>>} */
					const accountPrefs = {};
					for (const account of accounts) {
						const server = mailPrefs.getCharPref(`account.${account}.server`);
						const dkimAccountPrefs = Services.prefs.getBranch(`mail.server.${server}.dkim_verifier.`);
						const prefs = this._getChildPrefs(dkimAccountPrefs);
						if (Object.keys(prefs).length > 0) {
							accountPrefs[account] = prefs;
						}
					}
					return Promise.resolve(accountPrefs);
				},
			},
		};
	}
};
