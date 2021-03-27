/**
 * Migrates user data from the Legacy Overlay Extension.
 *
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../WebExtensions.d.ts" />
///<reference path="../experiments/migration.d.ts" />
/* eslint-env webextensions */

import prefs, { StorageLocalPreferences } from "../modules/preferences.mjs.js";
import ExtensionUtils from "./extensionUtils.mjs.js";
import Logging from "./logging.mjs.js";

const log = Logging.getLogger("Migration");

export async function migratePrefs() {
	const preferences = await ExtensionUtils.safeGetLocalStorage();
	if (preferences) {
		for (const dataStorageScope of StorageLocalPreferences.dataStorageScopes) {
			delete preferences[dataStorageScope];
		}
		if (Object.keys(preferences).length !== 0) {
			log.info("Skipping migration of preferences as browser.storage already has some set");
			return;
		}
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
			if (name === "policy.signRules.autoAddRule") {
				name = "policy.signRules.autoAddRule.enable";
			}
			await prefs.setValue(name, value);
		} catch (error) {
			log.error(`Migration of preference ${name} with value ${value} failed:`, error);
		}
	}

	const accountPrefs = await browser.migration.getAccountPrefs();
	for (const [account, accountPreferences] of Object.entries(accountPrefs)) {
		for (const [name, value] of Object.entries(accountPreferences)) {
			try {
				await prefs.setAccountValue(name, account, value);
			} catch (error) {
				log.error(`Migration of preference ${name} for account ${account} with value ${value} failed:`, error);
			}
		}
	}
}

export async function migrateSignRulesUser() {
	const storage = await ExtensionUtils.safeGetLocalStorage();
	if (storage && storage.signRulesUser) {
		log.info("Skipping migration of user sign rules as browser.storage already contains some");
		return;
	}

	const userRules = await browser.migration.getSignRulesUser();
	if (userRules) {
		await browser.storage.local.set({ signRulesUser: userRules });
	}
}

export async function migrateKeyStore() {
	const storage = await ExtensionUtils.safeGetLocalStorage();
	if (storage && storage.keyStore) {
		log.info("Skipping migration of stored keys as browser.storage already contains some");
		return;
	}

	const keyStore = await browser.migration.getDkimKeys();
	if (keyStore) {
		await browser.storage.local.set({ keyStore: keyStore });
	}
}
