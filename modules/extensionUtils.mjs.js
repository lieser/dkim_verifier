/*
 * Utility functions related to WebExtensions/MailExtensions.
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
/* eslint-env browser, webextensions */

/**
 * Reads a file included in the extension as a string.
 *
 * @param {string} path - path inside the extension of the file to read
 * @return {Promise<string>}
 */
async function readFile(path) {
	const url = browser.runtime.getURL(path);
	const req = new Request(url);
	const response = await fetch(req);
	const text = await response.text();
	return text;
}

const ExtensionUtils = {
	readFile: readFile,
};
export default ExtensionUtils;
