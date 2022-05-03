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
///<reference path="./mozilla.d.ts" />
/* global ExtensionCommon */

"use strict";

// eslint-disable-next-line no-invalid-this
this.storageMessage = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * @private
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
	 * @param {ExtensionCommon.Context} _context
	 * @returns {{storageMessage: browser.storageMessage}}
	 */
	getAPI(_context) {
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
