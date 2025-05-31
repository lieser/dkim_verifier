/**
 * Copyright (c) 2020-2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable no-magic-numbers */

import ExtensionUtils from "../modules/extensionUtils.mjs.js";
import Logging from "../modules/logging.mjs.js";
import { getElementById } from "./domUtils.mjs.js";
import prefs from "../modules/preferences.mjs.js";

const log = Logging.getLogger("Options");

/**
 * Set the active pane to the given navigation selector.
 *
 * @param {Element} navSelector
 * @returns {void}
 */
function setNavigation(navSelector) {
	// get the <nav> element the selector belongs to
	const navElement = navSelector.parentElement;
	if (!navElement) {
		log.warn("Failed to get parent nav element", navSelector);
		return;
	}
	// get the parent of the <nav> element, which should contain the panes
	const navParent = navElement.parentElement;
	if (!navParent) {
		log.warn("Failed to get parent of nav element", navElement);
		return;
	}

	// set selected attribute on navigation selectors
	const navSelectors = [...navElement.querySelectorAll(":scope>[pane]")];
	for (const selector of navSelectors) {
		selector.removeAttribute("selected");
	}
	navSelector.setAttribute("selected", "true");

	// show only selected pane
	const panes = /** @type {HTMLElement[]} */([...navParent.querySelectorAll(":scope>[pane]")]);
	for (const pane of panes) {
		pane.hidden = pane.getAttribute("pane") !== navSelector.getAttribute("pane");
	}
	navSelector.setAttribute("selected", "true");
}

/**
 * Add navigation logic to <nav> elements and initialize navigation.
 *
 * @returns {void}
 */
function initNavigation() {
	const navElements = [...document.querySelectorAll("nav")];
	for (const navElement of navElements) {
		const navSelectors = [...navElement.querySelectorAll(":scope>[pane]")];
		if (!navSelectors[0]) {
			throw new Error("No nav selector found under nav element.");
		}
		// initialize the navigation to the first navigation selector
		setNavigation(navSelectors[0]);
		// add navigation callback to click event
		for (const navSelector of navSelectors) {
			navSelector.addEventListener("click", () => {
				setNavigation(navSelector);
			});
		}
	}
}

/**
 * Update disabled states based on selected key storing.
 *
 * @returns {void}
 */
function updateKeyStoring() {
	/** @type {HTMLSelectElement|null} */
	const keyStoring = document.querySelector("[data-pref='key.storing']");
	if (!keyStoring) {
		throw new Error("key.storing element not found");
	}
	const viewKeys = getElementById("key.viewKeys");
	if (!(viewKeys instanceof HTMLButtonElement)) {
		throw new TypeError("key.viewKeys element is not a button");
	}

	viewKeys.disabled = Number.parseInt(keyStoring.value, 10) === 0;
}

/**
 * Update which DNS resolver settings are shown.
 *
 * @returns {void}
 */
function updateDnsResolver() {
	/** @type {HTMLSelectElement|null} */
	const dnsResolver = document.querySelector("[data-pref='dns.resolver']");
	if (!dnsResolver) {
		throw new Error("dns.resolver element not found");
	}

	const dnsResolverElements = /** @type {HTMLElement[]} */([...document.querySelectorAll("[data-dns-resolver]")]);
	for (const element of dnsResolverElements) {
		element.hidden = element.dataset.dnsResolver !== dnsResolver.value;
	}
}

/**
 * Update disabled states based on if the proxy is enabled.
 *
 * @returns {void}
 */
function updateDnsProxy() {
	/** @type {HTMLInputElement|null} */
	const dnsProxyEnable = document.querySelector("[data-pref='dns.proxy.enable']");
	if (!dnsProxyEnable) {
		throw new Error("dns.proxy.enable element not found");
	}
	const dnsProxy = getElementById("dns.proxy");
	if (!(dnsProxy instanceof HTMLFieldSetElement)) {
		throw new TypeError("dns.proxy element is not a fieldset");
	}

	dnsProxy.disabled = !dnsProxyEnable.checked;
}

/**
 * Updates the visibility of the usage warning for libunbound.
 *
 * @returns {void}
 */
function updateDnsLibunboundWarning() {
	const highlightUsageWarning = prefs["dns.libunbound.path"].trim() === "";
	const usageWarning = getElementById("libunbound.usageWarning");
	usageWarning.dataset.highlight = highlightUsageWarning.toString();
}

/**
 * Update disabled states based on if sign rules are enabled.
 *
 * @returns {void}
 */
function updatePolicySignRulesEnable() {
	/** @type {HTMLInputElement|null} */
	const policySignRulesEnable = document.querySelector("[data-pref='policy.signRules.enable']");
	if (!policySignRulesEnable) {
		throw new Error("policy.signRules.enable element not found");
	}
	const policySignRules = getElementById("policy.signRules");
	if (!(policySignRules instanceof HTMLFieldSetElement)) {
		throw new TypeError("policy.signRules element is not a fieldset");
	}

	policySignRules.disabled = !policySignRulesEnable.checked;
}

/**
 * Update disabled states based on if auto adding of sign rules is enabled.
 *
 * @returns {void}
 */
function updatePolicyAutoAddRuleEnable() {
	/** @type {HTMLInputElement|null} */
	const policySignRulesAutoAddRuleEnable =
		document.querySelector("[data-pref='policy.signRules.autoAddRule.enable']");
	if (!policySignRulesAutoAddRuleEnable) {
		throw new Error("policy.signRules.autoAddRule enabled element not found");
	}
	const policySignRulesAutoAddRule = getElementById("policy.signRules.autoAddRule");
	if (!(policySignRulesAutoAddRule instanceof HTMLFieldSetElement)) {
		throw new TypeError("policy.signRules.autoAddRule element is not a fieldset");
	}

	policySignRulesAutoAddRule.disabled = !policySignRulesAutoAddRuleEnable.checked;
}

/**
 * Set a preference based on a change event an a target.
 *
 * @param {string} prefName
 * @param {HTMLElement} target
 * @returns {Promise<void>}
 */
async function setPreference(prefName, target) {
	if (target instanceof HTMLInputElement) {
		if (target.getAttribute("type") === "checkbox") {
			await prefs.setValue(prefName, target.checked);
		} else if (target.getAttribute("type") === "text" ||
			target.dataset.prefType === "string"
		) {
			await prefs.setValue(prefName, target.value);
		} else if (target.getAttribute("type") === "number") {
			await prefs.setValue(prefName, Number.parseInt(target.value, 10));
		} else {
			log.error("Received change event for input element with unexpected type", event);
		}
	} else if (target instanceof HTMLSelectElement) {
		// eslint-disable-next-line unicorn/prefer-ternary
		if (target.dataset.prefType === "string") {
			await prefs.setValue(prefName, target.value);
		} else {
			await prefs.setValue(prefName, Number.parseInt(target.value, 10));
		}
	} else {
		log.error("Received change event for unexpected element", event);
	}

	switch (prefName) {
		case "key.storing": {
			updateKeyStoring();
			break;
		}
		case "dns.resolver": {
			updateDnsResolver();
			break;
		}
		case "dns.proxy.enable": {
			updateDnsProxy();
			break;
		}
		case "dns.libunbound.path": {
			updateDnsLibunboundWarning();
			break;
		}
		case "policy.signRules.enable": {
			updatePolicySignRulesEnable();
			break;
		}
		case "policy.signRules.autoAddRule.enable": {
			updatePolicyAutoAddRuleEnable();
			break;
		}
		default:
	}
}

/**
 * Set an account preference based on a change event an a target.
 *
 * @param {string} prefName
 * @param {HTMLElement} target
 * @returns {Promise<void>}
 */
async function setAccountPreference(prefName, target) {
	const accountSelectionBox = getElementById("account-selection-box");
	const account = accountSelectionBox.dataset.current;
	if (!account) {
		throw new Error("no account defined on account-selection element");
	}

	if (target instanceof HTMLInputElement) {
		await prefs.setAccountValue(prefName, account, target.value);
	} else if (target instanceof HTMLSelectElement) {
		await prefs.setAccountValue(prefName, account, Number.parseInt(target.value, 10));
	} else {
		log.error("Received change event for unexpected element", event);
	}
}

/**
 * React to a change event on an HTML element representing a preference.
 *
 * @param {Event} event
 * @returns {Promise<void>}
 */
async function preferenceChanged(event) {
	try {
		const target = event.target;
		if (!(target instanceof HTMLElement)) {
			log.warn("Received unexpected change event for non HTML element", event);
			return;
		}
		let prefName = target.dataset.pref;
		if (prefName) {
			await setPreference(prefName, target);
			return;
		}
		prefName = target.dataset.accountPref;
		if (prefName) {
			await setAccountPreference(prefName, target);
			return;
		}
		log.warn("Received unexpected change event for element without data-pref or data-account-pref attribute", event);
	} catch (error) {
		log.fatal("Unexpected error in preferenceChanged():", error);
	}
}

/**
 * Initialize logic for preferences.
 *
 * @returns {Promise<void>}
 */
async function initPreferences() {
	await prefs.init();

	// set prefs to initial value
	const prefElements = /** @type {HTMLElement[]} */([...document.querySelectorAll("[data-pref]")]);
	for (const element of prefElements) {
		const prefName = element.dataset.pref;
		if (!prefName) {
			log.error("Preference element has unexpected data-pref attribute", element);
			continue;
		}
		if (element instanceof HTMLInputElement) {
			if (element.getAttribute("type") === "checkbox") {
				element.checked = prefs.getBool(prefName);
			} else if (element.getAttribute("type") === "text" ||
				element.dataset.prefType === "string"
			) {
				element.value = prefs.getString(prefName);
			} else if (element.getAttribute("type") === "number") {
				element.value = prefs.getNumber(prefName).toString();
			} else {
				log.error("Input element has unexpected type", element);
			}
		} else if (element instanceof HTMLSelectElement) {
			element.value = element.dataset.prefType === "string"
				? prefs.getString(prefName)
				: prefs.getNumber(prefName).toString();
		} else {
			log.error("Unexpected preference element", element);
		}
	}

	updateKeyStoring();
	updateDnsResolver();
	updateDnsProxy();
	updateDnsLibunboundWarning();
	updatePolicySignRulesEnable();
	updatePolicyAutoAddRuleEnable();

	// listening to changes
	document.body.addEventListener("change", preferenceChanged);
}

/**
 * Update logic for account preferences.
 *
 * @param {string} account - account to show preferences for
 * @returns {void}
 */
function updateAccountPreferences(account) {
	const prefElements = /** @type {HTMLElement[]} */([...document.querySelectorAll("[data-account-pref]")]);
	for (const element of prefElements) {
		const prefName = element.dataset.accountPref;
		if (!prefName) {
			log.error("Preference element has unexpected data-account-pref attribute", element);
			continue;
		}
		if (element instanceof HTMLInputElement) {
			const value = prefs.getAccountValue(prefName, account);
			if (typeof value !== "string") {
				log.error("Account preference has unexpected type", element, value);
				continue;
			}
			element.value = value;
		} else if (element instanceof HTMLSelectElement) {
			element.value = prefs.getAccountValue(prefName, account).toString();
		} else {
			log.error("Unexpected preference element", element);
		}
	}
}

/**
 * Initialize logic for account specific settings.
 *
 * @returns {Promise<void>}
 */
async function initAccount() {
	await prefs.init();

	const accountSelectionBox = getElementById("account-selection-box");

	const accounts = (await browser.accounts.list()).
		filter(account =>
			account.type === "imap" ||
			account.type === "pop3" ||
			account.type === "none"
		);

	/** @type {HTMLDivElement[]} */
	const items = [];
	for (const account of accounts) {
		const item = document.createElement("div");
		item.classList.add("account-selection-item");
		item.textContent = account.name;
		item.addEventListener("click", () => {
			for (const i of items) {
				i.removeAttribute("selected");
			}
			item.setAttribute("selected", "true");
			accountSelectionBox.dataset.current = account.id;
			updateAccountPreferences(account.id);
		});
		items.push(item);

		// Parent needed for ::after opacity trick
		const parent = document.createElement("div");
		parent.style.position = "relative";
		parent.append(item);
		accountSelectionBox.append(parent);
	}

	// select first account at start
	items[0]?.click();
}

/**
 * Set click handlers for buttons.
 *
 * @returns {void}
 */
function initButtons() {
	const keysView = getElementById("key.viewKeys");
	keysView.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"/content/keysView.html",
		);
	});

	const signRulesDefaultsView = getElementById("signRulesDefaultsView");
	signRulesDefaultsView.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"/content/signRulesDefaultsView.html",
		);
	});

	const signRulesUserView = getElementById("signRulesUserView");
	signRulesUserView.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"/content/signRulesUserView.html",
			550,
			900
		);
	});
}

document.addEventListener("DOMContentLoaded", () => {
	initNavigation();
	initPreferences().
		catch(error => log.fatal("Unexpected error in initPreferences():", error));
	initAccount().
		catch(error => log.fatal("Unexpected error in initAccount():", error));
	initButtons();
}, { once: true });
