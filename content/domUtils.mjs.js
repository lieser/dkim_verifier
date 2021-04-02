/**
 * Copyright (c) 2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser */

/**
 * @param {string} id
 * @returns {HTMLElement}
 */
export function getElementById(id) {
	const element = document.getElementById(id);
	if (!element) {
		throw new Error(`Could not find element with id '${id}'.`);
	}
	return element;
}
