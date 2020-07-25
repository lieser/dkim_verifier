/**
 * Setup the global browser object and the extensionUtils module for the tests
 * environment.
 *
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import ExtensionUtils from "../../modules/extensionUtils.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import { readTextFile } from "./testUtils.mjs.js";

export let hasWebExtensions = false;
/** @type {import("webextensions-api-fake").BrowserFake} */
export let fakeBrowser;

ExtensionUtils.readFile = readTextFile;

/**
 * Parse a JSON file that contains comments in the form of "//…"
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
		// @ts-ignore
		globalThis.browser = fakeBrowser;
		hasWebExtensions = true;
	} catch (e) {
		// Ugly workaround for running tests for modules that use the global prefs in the browser
		prefs._valueGetter = (name) => { return prefs._prefs[name]; };
		prefs._valueSetter = (name, value) => { prefs._prefs[name] = value; return Promise.resolve(); };
		prefs.init = () => { return Promise.resolve(); };
		prefs.clear = () => { prefs._prefs = {}; return Promise.resolve(); };
		// Still allow adding stubs to browser namespace
		// @ts-expect-error
		globalThis.browser = {};
	}
});
