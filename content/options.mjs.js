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
 */
document.addEventListener("DOMContentLoaded", () => {
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
});
