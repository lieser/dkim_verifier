/**
 * Setup the global browser object and the extensionUtils module for the tests
 * environment.
 *
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable mocha/no-exports */

import ExtensionUtils from "../../modules/extensionUtils.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import { readTextFile } from "./testUtils.mjs.js";
import sinon from "./sinonUtils.mjs.js";
import { stringEndsWith } from "../../modules/utils.mjs.js";

export let hasWebExtensions = false;
/** @type {import("webextensions-api-fake").BrowserFake} */
export let fakeBrowser;

ExtensionUtils.readFile = readTextFile;

/**
 * Parse a JSON file that contains comments in the form of "//…".
 *
 * @param {string} data
 * @returns {any}
 */
function jsonParse(data) {
	const dataWithoutComments = data.
		split("\n").
		filter(line => !line.trimStart().startsWith("//")).
		join("\n");
	return JSON.parse(dataWithoutComments);
}

/**
 * Returns the base domain for an e-mail address.
 *
 * @param {string} addr
 * @returns {Promise<string>}
 */
function getBaseDomainFromAddr(addr) {
	const publicSuffixList = [
		"co.uk",
	];
	let numberDomainParts = 2;
	if (publicSuffixList.some(suffix => stringEndsWith(addr, suffix))) {
		numberDomainParts = 3;
	}
	const fullDomain = addr.substr(addr.lastIndexOf("@") + 1);
	const domainParts = fullDomain.split(".");
	const baseDomain = domainParts.slice(-numberDomainParts).join(".");
	return Promise.resolve(baseDomain);
}

// eslint-disable-next-line mocha/no-top-level-hooks
before(async function () {
	try {
		const { default: browserFake } = await import("webextensions-api-fake");
		/** @type {import("webextensions-api-fake").WebExtensionsApiFakeOptions} */
		const options = {
			locales: {
				"en-US": jsonParse(await readTextFile("_locales/en_US/messages.json")),
			},
		};
		// workaround for https://github.com/stoically/webextensions-api-fake/issues/4
		// @ts-expect-error
		if (browserFake.default) {
			// @ts-expect-error
			fakeBrowser = browserFake.default(options);
		} else {
			fakeBrowser = browserFake(options);
		}
		// @ts-expect-error
		globalThis.browser = fakeBrowser;
		hasWebExtensions = true;
	} catch (e) {
		// Ugly workaround for running tests for modules that use the global prefs in the browser
		// @ts-expect-error
		prefs._valueGetter = (name) => { return prefs._prefs[name]; };
		// @ts-expect-error
		prefs._valueSetter = (name, value) => { prefs._prefs[name] = value; return Promise.resolve(); };
		prefs.init = () => { return Promise.resolve(); };
		// @ts-expect-error
		prefs.clear = () => { prefs._prefs = {}; return Promise.resolve(); };
		// Still allow adding stubs to browser namespace
		globalThis.browser = {
			// @ts-expect-error
			runtime: {},
		};
	}

	globalThis.browser.runtime.sendMessage = sinon.fake.resolves(undefined);

	globalThis.browser.accounts = {
		list: sinon.fake.resolves([]),
		get: sinon.fake.resolves(null),
		getDefault: sinon.fake.throws("no fake for browser.accounts.getDefault"),
		setDefaultIdentity: sinon.fake.throws("no fake for browser.accounts.setDefaultIdentity"),
		getDefaultIdentity: sinon.fake.throws("no fake for browser.accounts.getDefaultIdentity"),
		onCreated: {
			addListener: sinon.fake.throws("no fake for browser.accounts.onCreated.addListener"),
			removeListener: sinon.fake.throws("no fake for browser.accounts.onCreated.removeListener"),
			hasListener: sinon.fake.throws("no fake for browser.accounts.onCreated.hasListener"),
		},
		onDeleted: {
			addListener: sinon.fake.throws("no fake for browser.accounts.onDeleted.addListener"),
			removeListener: sinon.fake.throws("no fake for browser.accounts.onDeleted.removeListener"),
			hasListener: sinon.fake.throws("no fake for browser.accounts.onDeleted.hasListener"),
		},
		onUpdated: {
			addListener: sinon.fake.throws("no fake for browser.accounts.onUpdated.addListener"),
			removeListener: sinon.fake.throws("no fake for browser.accounts.onUpdated.removeListener"),
			hasListener: sinon.fake.throws("no fake for browser.accounts.onUpdated.hasListener"),
		},
	};

	globalThis.browser.mailUtils = {
		getBaseDomainFromAddr,
	};
});
