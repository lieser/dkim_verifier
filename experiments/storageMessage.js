/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./storageMessage.d.ts" />
///<reference path="../mozilla.d.ts" />
/* eslint-env worker */
/* global ExtensionCommon */

"use strict";

// eslint-disable-next-line no-invalid-this
this.storageMessage = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * @param {number} messageId
	 * @returns {nsIMsgDBHdr}
	 */
	_getMsgHdr(messageId) {
		const msgHdr = this.extension.messageManager.get(messageId);
		if (!msgHdr.folder) {
			throw new Error("Cannot set/get data on an external message");
		}
		return msgHdr;
	}

	/**
	 * @param {ExtensionCommon.Context} context
	 * @returns {{storageMessage: browser.storageMessage}}
	 */
	// eslint-disable-next-line no-unused-vars
	getAPI(context) {
		return {
			storageMessage: {
				set: (messageId, key, value) => {
					const msgHdr = this._getMsgHdr(messageId);
					msgHdr.setStringProperty(key, value);
					return Promise.resolve();
				},
				get: (messageId, key) => {
					const msgHdr = this._getMsgHdr(messageId);
					const value = msgHdr.getStringProperty(key);
					return Promise.resolve(value);
				},
			},
		};
	}
};
