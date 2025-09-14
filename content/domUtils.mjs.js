/**
 * Copyright (c) 2021-2022;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

import { Deferred } from "../modules/utils.mjs.js";

// @ts-check

/**
 * @param {string} id
 * @returns {HTMLElement}
 */
export function getElementById(id) {
	const element = document.getElementById(id);
	if (!element) {
		throw new Error(`Could not find element with id '${id}'.`);
	}
	return element;
}

/**
 * Upload JSON data.
 *
 * @returns {Promise<any>}
 */
export function uploadJsonData() {
	const deferredData = new Deferred();
	const inputElement = document.createElement("input");
	inputElement.type = "file";
	inputElement.accept = "application/json";
	inputElement.addEventListener("change", async (_event) => {
		try {
			if (!inputElement.files || !inputElement.files[0]) {
				throw new Error("Input element has no file");
			}

			const file = await inputElement.files[0].text();
			deferredData.resolve(JSON.parse(file));
		} catch (error) {
			deferredData.reject(error);
		}
	});
	inputElement.click();
	return deferredData.promise;
}
