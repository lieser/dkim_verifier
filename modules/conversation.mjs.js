/**
 * Push the authentication result to the Conversation add-on.
 *
 * Copyright (c) 2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../WebExtensions.d.ts" />
/* eslint-env webextensions */

import AuthVerifier from "../modules/authVerifier.mjs.js";
import Logging from "./logging.mjs.js";

const log = Logging.getLogger("Conversation");

/**
 * @typedef {"normal"|"success"|"warning"|"error"} Severity
 */

/**
 * @typedef {object} AddPillMessage
 * @property {"addPill"} type
 *  The type of the received message.
 * @property {number} msgId
 *   The id of the associated Message from the WebExtension APIs.
 * @property {Severity} [severity]
 *   The severity of the pill. Defaults to normal.
 * @property {string} [icon]
 *   The optional icon of the pill. Musst be an "moz-extension://" url.
 * @property {string} message
 *   The text of the pill.
 * @property {string[]} [tooltip]
 *   The optional tooltip of the pill.
 */

/** @type {browser.runtime.Port?} */
let port = null;

/**
 * Add a pill in Conversation.
 *
 * @param {number} msgId
 * @param {Severity|undefined} severity
 * @param {string|undefined} icon
 * @param {string} message
 * @param {string[]|undefined} tooltip
 * @returns {void}
 */
function addPill(msgId, severity, icon, message, tooltip) {
	/** @type {AddPillMessage} */
	const runtimeMessage = {
		type: "addPill",
		msgId,
		severity,
		icon,
		message,
		tooltip,
	};
	if (!port) {
		port = browser.runtime.connect("gconversation@xulforum.org");
		port.onDisconnect.addListener((p) => {
			log.debug("Port to Conversation was disconnected", p.error);
			port = null;
		});
	}
	port.postMessage(runtimeMessage);
}

const verifier = new AuthVerifier();

/**
 * Verify a message and display the result in Conversation.
 *
 * @param {browser.messageDisplay.MessageHeader} MessageHeader
 * @returns {Promise<void>}
 */
export default async function verifyMessage(MessageHeader) {
	const res = await verifier.verify(MessageHeader);
	if (!res.dkim[0]) {
		throw new Error("Result does not contain a DKIM result.");
	}

	/** @type {Severity} */
	let severity;
	let message;
	let tooltip;
	switch (res.dkim[0].res_num) {
		case AuthVerifier.DKIM_RES.SUCCESS: {
			const dkim = res.dkim[0];
			if (!dkim.warnings_str || dkim.warnings_str.length === 0) {
				severity = "success";
			} else {
				severity = "warning";
			}
			message = browser.i18n.getMessage("SUCCESS_TAG", dkim.sdid);
			tooltip = res.dkim[0].warnings_str;
			break;
		}
		case AuthVerifier.DKIM_RES.TEMPFAIL:
			severity = "normal";
			message = browser.i18n.getMessage("TEMPFAIL_TAG");
			tooltip = [res.dkim[0].result_str];
			break;
		case AuthVerifier.DKIM_RES.PERMFAIL:
			severity = "error";
			message = browser.i18n.getMessage("PERMFAIL_TAG");
			if (res.dkim[0].error_str) {
				tooltip = [res.dkim[0].error_str];
			}
			break;
		case AuthVerifier.DKIM_RES.PERMFAIL_NOSIG:
		case AuthVerifier.DKIM_RES.NOSIG:
			return;
		default:
			throw new Error(`unknown res_num: ${res.dkim[0].res_num}`);
	}

	addPill(MessageHeader.id, severity, res.dkim[0].favicon, message, tooltip);
}
