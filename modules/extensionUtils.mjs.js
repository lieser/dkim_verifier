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
 * Create popup window, or raise it if already open.
 *
 * @param {string} url
 * @param {string} title
 * @param {number} [height]
 * @param {number} [width]
 * @return {Promise<browser.windows.Window>}
 */
async function createOrRaisePopup(url, title, height = undefined, width = undefined) {
	const popupWindows = await browser.windows.getAll({
		populate: true,
		windowTypes: ["popup"],
	});
	const popupWindow = popupWindows.find(popup => popup.title === `${title} - Mozilla Thunderbird`);
	if (popupWindow?.id !== undefined) {
		await browser.windows.update(popupWindow.id, { focused: true });
		return popupWindow;
	}
	return browser.windows.create({
		url: url,
		type: "popup",
		allowScriptsToClose: true,
		height: height,
		width: width,
	});
}

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
	createOrRaisePopup: createOrRaisePopup,
	readFile: readFile,
};
export default ExtensionUtils;
