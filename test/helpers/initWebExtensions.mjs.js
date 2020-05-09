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
/** @type {import("webextensions-api-fake/dist").BrowserFake} */
export let fakeBrowser;

ExtensionUtils.readFile = readTextFile;

before(async function () {
	try {
		const { default: browserFake } = await import("webextensions-api-fake");
		// workaround for https://github.com/stoically/webextensions-api-fake/issues/4
		if (browserFake.default) {
			fakeBrowser = browserFake.default();
		} else {
			fakeBrowser = browserFake();
		}
		// @ts-ignore
		globalThis.browser = fakeBrowser;
		hasWebExtensions = true;
	} catch (e) {
		// Ugly workaround for running tests for modules that use the global prefs in the browser
		prefs._valueGetter = (name) => { return prefs._prefs[name]; };
		prefs.init = () => { return Promise.resolve(); };
		prefs.clear = () => { prefs._prefs = {}; return Promise.resolve(); };
	}
});
