/**
 * Copyright (c) 2021-2024 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../RuntimeMessage.d.ts" />
/* eslint-env webextensions */

import { getElementById } from "./domUtils.mjs.js";

class KeyValueElement extends HTMLElement {
	#label;

	constructor() {
		super();

		const shadow = this.attachShadow({ mode: "open" });
		const content = document.createElement("div");
		content.style.display = "flex";
		content.style.flexDirection = "row";
		shadow.appendChild(content);

		this.#label = document.createElement("p");
		this.#label.style.margin = "0 .45em 0 0";

		const value = document.createElement("slot");

		content.appendChild(this.#label);
		content.appendChild(value);
	}

	connectedCallback() {
		this.#label.textContent = `${this.getAttribute("key")}:`;
	}
}
customElements.define("key-value", KeyValueElement);

class ValueTextElement extends HTMLElement {
	#value;

	constructor() {
		super();

		const shadow = this.attachShadow({ mode: "open" });

		this.#value = document.createElement("p");
		this.#value.style.margin = "0px";

		shadow.appendChild(this.#value);
	}

	connectedCallback() {
		this.#value.textContent = `${this.getAttribute("value")}`;
	}
}
customElements.define("value-text", ValueTextElement);

class ValueWarningsElement extends HTMLElement {
	/** @type {string[]} */
	warnings = [];
	#content;

	constructor() {
		super();

		const shadow = this.attachShadow({ mode: "open" });
		this.#content = document.createElement("div");
		this.#content.style.display = "flex";
		this.#content.style.flexDirection = "column";
		shadow.appendChild(this.#content);
	}

	connectedCallback() {
		// Delete old warnings.
		this.#content.replaceChildren();

		for (const warning of this.warnings) {
			const warningElement = document.createElement("p");
			warningElement.style.margin = "0px";
			warningElement.textContent = warning;
			this.#content.appendChild(warningElement);
		}
	}
}
customElements.define("value-warnings", ValueWarningsElement);

class DkimResult extends HTMLElement {
	/** @type {import("../modules/authVerifier.mjs.js").AuthResultDKIM|null} */
	result = null;
	#content;

	constructor() {
		super();

		const shadow = this.attachShadow({ mode: "open" });
		this.#content = document.createElement("div");
		this.#content.style.margin = "4px";
		this.#content.style.padding = ".45em 1em";
		this.#content.style.border = "1px solid";
		this.#content.style.borderRadius = "4px";
		this.#content.style.display = "flex";
		this.#content.style.flexDirection = "column";
		this.#content.style.columnGap = "1em";
		this.#content.style.rowGap = ".45em";
		shadow.appendChild(this.#content);
	}

	connectedCallback() {
		if (!this.result) {
			throw new Error("A DkimResult musst have a result bevor it can be connected.");
		}

		DkimResult.#addTextValue(this.#content, "Result", this.result?.result_str);
		DkimResult.#addOptionalWarnings(this.#content, "Warnings", this.result?.warnings_str);
		DkimResult.#addTextValue(this.#content, "SDID", this.result?.sdid ?? "Unknown");
		DkimResult.#addOptionalTextValue(this.#content, "AUID", this.result?.auid);
		DkimResult.#addOptionalTimeValue(this.#content, "Sign date", this.result?.timestamp);
		DkimResult.#addOptionalTimeValue(this.#content, "Expiration date", this.result?.expiration);
		DkimResult.#addOptionalTextValue(this.#content, "Algorithm", this.#algorithm());
		DkimResult.#addOptionalTextValue(this.#content, "Signed headers", this.result?.signedHeaders?.join(", "));
	}

	/**
	 * Get a string description of the used algorithm.
	 *
	 * @returns {string|undefined}
	 */
	#algorithm() {
		if (!this.result?.algorithmSignature || !this.result?.algorithmHash) {
			return undefined;
		}
		const signature = (() => {
			switch (this.result?.algorithmSignature) {
				case "rsa": {
					const name = "RSA";
					if (this.result.keyLength) {
						return `${name} (${this.result.keyLength} bits)`;
					}
					return name;
				}
				case "ed25519": {
					return "Ed25519";
				}
				default: {
					return this.result?.algorithmSignature;
				}
			}
		})();
		const hash = (() => {
			switch (this.result?.algorithmHash) {
				case "sha1": {
					return "SHA-1";
				}
				case "sha256": {
					return "SHA-256";
				}
				default: {
					return this.result?.algorithmHash;
				}
			}
		})();
		return `${signature} / ${hash}`;
	}

	/**
	 * Add a text value to an element under the specified key.
	 *
	 * @param {Node} parent
	 * @param {string} key
	 * @param {string} value
	 */
	static #addTextValue(parent, key, value) {
		const valueElement = new ValueTextElement();
		valueElement.setAttribute("value", value);

		const element = new KeyValueElement();
		element.setAttribute("key", key);

		element.appendChild(valueElement);
		parent.appendChild(element);
	}

	/**
	 * Optionally add a text value to an element under the specified key.
	 *
	 * @param {Node} parent
	 * @param {string} key
	 * @param {string|undefined} value
	 */
	static #addOptionalTextValue(parent, key, value) {
		if (value) {
			DkimResult.#addTextValue(parent, key, value);
		}
	}

	/**
	 * Optionally add a time value to an element under the specified key.
	 *
	 * @param {Node} parent
	 * @param {string} key
	 * @param {number|null|undefined} value
	 */
	static #addOptionalTimeValue(parent, key, value) {
		if (value) {
			// eslint-disable-next-line no-magic-numbers
			DkimResult.#addTextValue(parent, key, new Date(value * 1000).toString());
		} else if (value === null) {
			DkimResult.#addTextValue(parent, key, "None");
		}
	}

	/**
	 * Add a warning value to an element under the specified key.
	 *
	 * @param {Node} parent
	 * @param {string} key
	 * @param {string[]|undefined} warnings
	 */
	static #addOptionalWarnings(parent, key, warnings) {
		if (!warnings?.length) {
			return;
		}

		const valueElement = new ValueWarningsElement();
		valueElement.warnings = warnings;

		const element = new KeyValueElement();
		element.setAttribute("key", key);

		element.appendChild(valueElement);
		parent.appendChild(element);
	}
}
customElements.define("dkim-result-extended", DkimResult);

/**
 * @returns {Promise<number>}
 */
async function getCurrentTabId() {
	const tab = await browser.tabs.query({ currentWindow: true, active: true });
	const tabId = tab[0]?.id;
	if (tabId === undefined) {
		throw new Error("active tab has no id");
	}
	return tabId;
}

/**
 * Trigger a display action and close the popup.
 *
 * @param {string} action
 * @returns {Promise<void>}
 */
async function triggerDisplayAction(action) {
	const tabId = await getCurrentTabId();
	/** @type {RuntimeMessage.DisplayAction.DisplayActionMessage} */
	const message = {
		module: "DisplayAction",
		method: action,
		parameters: {
			tabId,
		},
	};
	// Closing the window means getting the response (which we are not interested in) from sendMessage fails,
	// resulting in the following error that can be ignored:
	// Promise rejected after context unloaded: Actor 'Conduits' destroyed before query 'RuntimeMessage' was resolved
	browser.runtime.sendMessage(message);
	window.close();
}

/**
 * Query which buttons should be enabled.
 *
 * @returns {Promise<RuntimeMessage.DisplayAction.queryResultStateResult>}
 */
async function queryResultState() {
	const tabId = await getCurrentTabId();
	/** @type {RuntimeMessage.DisplayAction.DisplayActionMessage} */
	const message = {
		module: "DisplayAction",
		method: "queryResultState",
		parameters: {
			tabId,
		},
	};
	return browser.runtime.sendMessage(message);
}

document.addEventListener("DOMContentLoaded", async () => {
	const resultState = await queryResultState();

	const results = getElementById("results");
	for (const res of resultState.dkim) {
		const resElement = new DkimResult();
		resElement.result = res;
		results.appendChild(resElement);
	}

	const reverifyDKIMSignature = getElementById("reverifyDKIMSignature");
	if (!(reverifyDKIMSignature instanceof HTMLButtonElement)) {
		throw new Error("reverifyDKIMSignature element is not a button");
	}
	reverifyDKIMSignature.addEventListener("click", async () => {
		await triggerDisplayAction("reverifyDKIMSignature");
	});
	if (resultState.reverifyDKIMSignature) {
		reverifyDKIMSignature.disabled = false;
	}

	const policyAddUserException = getElementById("policyAddUserException");
	if (!(policyAddUserException instanceof HTMLButtonElement)) {
		throw new Error("policyAddUserException element is not a button");
	}
	policyAddUserException.addEventListener("click", async () => {
		await triggerDisplayAction("policyAddUserException");
	});
	if (resultState.policyAddUserException) {
		policyAddUserException.disabled = false;
	}

	const markKeyAsSecure = getElementById("markKeyAsSecure");
	if (!(markKeyAsSecure instanceof HTMLButtonElement)) {
		throw new Error("markKeyAsSecure element is not a button");
	}
	markKeyAsSecure.addEventListener("click", async () => {
		await triggerDisplayAction("markKeyAsSecure");
	});
	if (resultState.markKeyAsSecure) {
		markKeyAsSecure.disabled = false;
	}

	const updateKey = getElementById("updateKey");
	if (!(updateKey instanceof HTMLButtonElement)) {
		throw new Error("updateKey element is not a button");
	}
	updateKey.addEventListener("click", async () => {
		await triggerDisplayAction("updateKey");
	});
	if (resultState.updateKey) {
		updateKey.disabled = false;
	}

}, { once: true });
