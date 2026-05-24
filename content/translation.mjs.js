/**
 * Copyright (c) 2020-2021;2025-2026 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

/**
 * Add translations to document
 */
document.addEventListener("DOMContentLoaded", () => {
	const elements = /** @type {HTMLElement[]} */([...document.querySelectorAll("[data-i18n]")]);
	for (const element of elements) {
		const messageName = element.dataset.i18n;
		if (messageName) {
			element.insertAdjacentText("beforeend", browser.i18n.getMessage(messageName));
		}
	}
	const titleElements = /** @type {HTMLElement[]} */([...document.querySelectorAll("[data-i18n-title]")]);
	for (const element of titleElements) {
		const messageName = element.dataset.i18nTitle;
		if (messageName) {
			element.title = browser.i18n.getMessage(messageName);
		}
	}
}, { once: true });
