/**
 * Proxy to a singleton KeyDb to avoid problems with race conditions
 * when accessing browser.storage.local.
 *
 * Copyright (c) 2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../WebExtensions.d.ts" />
///<reference path="../../RuntimeMessage.d.ts" />
/* eslint-env webextensions */

export default class KeyDbProxy {
	// eslint-disable-next-line valid-jsdoc
	/**
	 * @type {typeof import("./keyStore.mjs.js").KeyDb["getKeys"]}}
	 */
	static getKeys() {
		/** @type {RuntimeMessage.KeyDb.getKeys} */
		const message = {
			module: "KeyDb",
			method: "getKeys",
		};
		return browser.runtime.sendMessage(message);
	}

	/**
	 * Update the key with the given id.
	 *
	 * @param {number} id
	 * @param {string} propertyName
	 * @param {any} newValue
	 * @returns {Promise<void>}
	 */
	static update(id, propertyName, newValue) {
		/** @type {RuntimeMessage.KeyDb.updateKey} */
		const message = {
			module: "KeyDb",
			method: "updateKey",
			parameters: {
				id: id,
				propertyName: propertyName,
				newValue: newValue,
			},
		};
		return browser.runtime.sendMessage(message);
	}

	/**
	 * Delete the key with the given id.
	 *
	 * @param {number} id
	 * @returns {Promise<void>}
	 */
	static delete(id) {
		/** @type {RuntimeMessage.KeyDb.deleteKey} */
		const message = {
			module: "KeyDb",
			method: "deleteKey",
			parameters: {
				id: id,
			},
		};
		return browser.runtime.sendMessage(message);
	}
}
