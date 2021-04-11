/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../WebExtensions.d.ts" />
/* eslint-env browser, webextensions */

import ExtensionUtils from "../modules/extensionUtils.mjs.js";
import Logging from "../modules/logging.mjs.js";
import { getElementById } from "./domUtils.mjs.js";
import prefs from "../modules/preferences.mjs.js";

const log = Logging.getLogger("Options");

/**
 * Set the active pane to the given navigation selector
 *
 * @param {HTMLElement} navSelector
 * @returns {void}
 */
function setNavigation(navSelector) {
	// get the <nav> element the selector belongs to
	const navElement = navSelector.parentElement;
	if (!navElement) {
		console.warn("Failed to get parent nav element", navSelector);
		return;
	}
	// get the parent of the <nav> element, which should contain the panes
	const navParent = navElement.parentElement;
	if (!navParent) {
		console.warn("Failed to get parent of nav element", navElement);
		return;
	}

	// set selected attribute on navigation selectors
	/** @type {HTMLElement[]} */
	const navSelectors = Array.from(navElement.querySelectorAll(":scope>[pane]"));
	for (const selector of navSelectors) {
		selector.removeAttribute("selected");
	}
	navSelector.setAttribute("selected", "true");

	// show only selected pane
	/** @type {HTMLElement[]} */
	const panes = Array.from(navParent.querySelectorAll(":scope>[pane]"));
	for (const pane of panes) {
		if (pane.getAttribute("pane") === navSelector.getAttribute("pane")) {
			pane.hidden = false;
		}
		else {
			pane.hidden = true;
		}
	}
	navSelector.setAttribute("selected", "true");
}

/**
 * Add navigation logic to <nav> elements and initialize navigation.
 *
 * @returns {void}
 */
function initNavigation() {
	const navElements = Array.from(document.querySelectorAll("nav"));
	for (const navElement of navElements) {
		/** @type {HTMLElement[]} */
		const navSelectors = Array.from(navElement.querySelectorAll(":scope>[pane]"));
		// initialize the navigation to the first navigation selector
		setNavigation(navSelectors[0]);
		// add navigation callback to click event
		for (const navSelector of navSelectors) {
			navSelector.onclick = () => {
				setNavigation(navSelector);
			};
		}
	}
}

function updateKeyStoring() {
	/** @type {HTMLSelectElement|null} */
	const keyStoring = document.querySelector("[data-pref='key.storing']");
	if (!keyStoring) {
		throw Error("key.storing element not found");
	}
	const viewKeys = getElementById("key.viewKeys");
	if (!(viewKeys instanceof HTMLButtonElement)) {
		throw Error("key.viewKeys element is not a button");
	}

	viewKeys.disabled = parseInt(keyStoring.value, 10) === 0;
}

function updateDnsResolver() {
	/** @type {HTMLSelectElement|null} */
	const dnsResolver = document.querySelector("[data-pref='dns.resolver']");
	if (!dnsResolver) {
		throw Error("dns.resolver element not found");
	}

	/** @type {HTMLElement[]} */
	const dnsResolverElements = Array.from(document.querySelectorAll("[data-dns-resolver]"));
	for (const element of dnsResolverElements) {
		element.hidden = element.dataset.dnsResolver !== dnsResolver.value;
	}
}

function updateDnsProxy() {
	/** @type {HTMLInputElement|null} */
	const dnsProxyEnable = document.querySelector("[data-pref='dns.proxy.enable']");
	if (!dnsProxyEnable) {
		throw Error("dns.proxy.enable element not found");
	}
	const dnsProxy = getElementById("dns.proxy");
	if (!(dnsProxy instanceof HTMLFieldSetElement)) {
		throw Error("dns.proxy element is not a fieldset");
	}

	dnsProxy.disabled = !dnsProxyEnable.checked;
}

function updateDnsLibunboundWarning() {
	const highlightUsageWarning = prefs["dns.libunbound.path"].trim() === "";
	const usageWarning = getElementById("libunbound.usageWarning");
	usageWarning.dataset.highlight = highlightUsageWarning.toString();
}

function updatePolicySignRulesEnable() {
	/** @type {HTMLInputElement|null} */
	const policySignRulesEnable = document.querySelector("[data-pref='policy.signRules.enable']");
	if (!policySignRulesEnable) {
		throw Error("policy.signRules.enable element not found");
	}
	const policySignRules = getElementById("policy.signRules");
	if (!(policySignRules instanceof HTMLFieldSetElement)) {
		throw Error("policy.signRules element is not a fieldset");
	}

	policySignRules.disabled = !policySignRulesEnable.checked;
}

function updatePolicyAutoAddRuleEnable() {
	/** @type {HTMLInputElement|null} */
	const policySignRulesAutoAddRuleEnable =
		document.querySelector("[data-pref='policy.signRules.autoAddRule.enable']");
	if (!policySignRulesAutoAddRuleEnable) {
		throw Error("policy.signRules.autoAddRule enabled element not found");
	}
	const policySignRulesAutoAddRule = getElementById("policy.signRules.autoAddRule");
	if (!(policySignRulesAutoAddRule instanceof HTMLFieldSetElement)) {
		throw Error("policy.signRules.autoAddRule element is not a fieldset");
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
			await prefs.setValue(prefName, parseInt(target.value, 10));
		} else {
			log.error("Received change event for input element with unexpected type", event);
		}
	} else if (target instanceof HTMLSelectElement) {
		if (target.dataset.prefType === "string") {
			await prefs.setValue(prefName, target.value);
		} else {
			await prefs.setValue(prefName, parseInt(target.value, 10));
		}
	} else {
		log.error("Received change event for unexpected element", event);
	}

	switch (prefName) {
		case "key.storing":
			updateKeyStoring();
			break;
		case "dns.resolver":
			updateDnsResolver();
			break;
		case "dns.proxy.enable":
			updateDnsProxy();
			break;
		case "dns.libunbound.path":
			updateDnsLibunboundWarning();
			break;
		case "policy.signRules.enable":
			updatePolicySignRulesEnable();
			break;
		case "policy.signRules.autoAddRule.enable":
			updatePolicyAutoAddRuleEnable();
			break;
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
		await prefs.setAccountValue(prefName, account, parseInt(target.value, 10));
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
	} catch (e) {
		log.fatal("Unexpected error in preferenceChanged():", e);
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
	/** @type {HTMLElement[]} */
	const prefElements = Array.from(document.querySelectorAll("[data-pref]"));
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
			if (element.dataset.prefType === "string") {
				element.value = prefs.getString(prefName);
			} else {
				element.value = prefs.getNumber(prefName).toString();
			}
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
	/** @type {HTMLElement[]} */
	const prefElements = Array.from(document.querySelectorAll("[data-account-pref]"));
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
		item.innerText = account.name;
		item.onclick = () => {
			for (const i of items) {
				i.removeAttribute("selected");
			}
			item.setAttribute("selected", "true");
			accountSelectionBox.dataset.current = account.id;
			updateAccountPreferences(account.id);
		};
		items.push(item);

		accountSelectionBox.appendChild(item);
	}

	// select first account at start
	items[0].click();
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
			"./keysView.html",
			browser.i18n.getMessage("options_key.viewKeys"),
		);
	});

	const signRulesDefaultsView = getElementById("signRulesDefaultsView");
	signRulesDefaultsView.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"./signRulesDefaultsView.html",
			browser.i18n.getMessage("options_viewSignerDefaults"),
		);
	});

	const signRulesUserView = getElementById("signRulesUserView");
	signRulesUserView.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"./signRulesUserView.html",
			browser.i18n.getMessage("options_viewSigners"),
		);
	});
}

document.addEventListener("DOMContentLoaded", () => {
	initNavigation();
	initPreferences().
		catch(e => log.fatal("Unexpected error in initPreferences():", e));
	initAccount().
		catch(e => log.fatal("Unexpected error in initAccount():", e));
	initButtons();
}, { once: true });
