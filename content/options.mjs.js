/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser */

import Logging from "../modules/logging.mjs.js";
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

/**
 * React to a change event on an HTML element representing a preference.
 *
 * @param {Event} event
 * @returns {void}
 */
function preferenceChanged(event) {
	try {
		const target = event.target;
		if (!(target instanceof HTMLElement)) {
			log.warn("Received unexpected change event for non HTML element", event);
			return;
		}
		const prefName = target.dataset.pref;
		if (!prefName) {
			log.warn("Received unexpected change event for element without data-pref attribute", event);
			return;
		}
		if (target instanceof HTMLInputElement) {
			if (target.getAttribute("type") === "checkbox") {
				prefs.setValue(prefName, target.checked);
			} else if (target.getAttribute("type") === "text" ||
				target.dataset.prefType === "string"
			) {
				prefs.setValue(prefName, target.value);
			} else if (target.getAttribute("type") === "number") {
				prefs.setValue(prefName, parseInt(target.value, 10));
			} else {
				log.error("Received change event for input element without unexpected type", event);
			}
		} else if (target instanceof HTMLSelectElement) {
			if (target.dataset.prefType === "string") {
				prefs.setValue(prefName, target.value);
			} else {
				prefs.setValue(prefName, parseInt(target.value, 10));
			}
		} else {
			log.error("Received change event for unexpected element", event);
		}
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

	// listening to changes
	document.body.addEventListener("change", preferenceChanged);
}

document.addEventListener("DOMContentLoaded", () => {
	initNavigation();
	initPreferences().
		catch(e => log.fatal("Unexpected error in initPreferences():", e));
});
