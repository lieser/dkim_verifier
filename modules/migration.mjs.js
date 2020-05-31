/*
 * Migrates user data from the Legacy Overlay Extension.
 *
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../WebExtensions.d.ts" />
/* eslint-env webextensions */

import Logging from "./logging.mjs.js";
import prefs from "../modules/preferences.mjs.js";

const log = Logging.getLogger("Migration");

export async function migratePrefs() {
	const preferences = await browser.storage.local.get();
	if (preferences && Object.keys(preferences).length !== 0) {
		log.info("Skipping migration of preferences as browser.storage already has some set");
		return;
	}
	await prefs.init();

	const userPrefs = await browser.migration.getUserPrefs();
	for (let [name, value] of Object.entries(userPrefs)) {
		try {
			if (name === "dns.proxy.port" && typeof value === "string") {
				value = parseInt(value, 10);
			}
			if (name === "error.policy.wrong_sdid.asWarning") {
				name = "policy.signRules.error.wrong_sdid.asWarning";
			}
			await prefs.setValue(name, value);
		} catch (error) {
			log.error(`Migration of preference ${name} with value ${value} failed:`, error);
		}
	}
}
