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
const { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");

// eslint-disable-next-line no-invalid-this
this.migration = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * @param {ExtensionCommon.Context} context
	 * @returns {{migration: browser.migration}}
	 */
	// eslint-disable-next-line no-unused-vars
	getAPI(context) {
		const PREF_BRANCH = "extensions.dkim_verifier.";
		const prefs = Services.prefs.getBranch(PREF_BRANCH);
		return {
			migration: {
				getUserPrefs: () => {
					const setPrefNames = prefs.getChildList("");
					/** @type {Object.<string, boolean|number|string>} */
					const userPrefs = {};
					for (const prefName of setPrefNames) {
						prefs.getPrefType(prefName);
						switch (prefs.getPrefType(prefName)) {
							case prefs.PREF_BOOL:
								userPrefs[prefName] = prefs.getBoolPref(prefName);
								break;
							case prefs.PREF_INT:
								userPrefs[prefName] = prefs.getIntPref(prefName);
								break;
							case prefs.PREF_STRING:
								userPrefs[prefName] = prefs.getCharPref(prefName);
								break;
							default:
								console.warn(`Preference ${prefName} has unexpected type ${prefs.getPrefType(prefName)}`);
						}
					}
					return Promise.resolve(userPrefs);
				},
			},
		};
	}
};
