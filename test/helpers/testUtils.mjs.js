/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser, node */

function isNodeJs() {
	return typeof window === 'undefined';
}

/**
 * Read a text file from the test data directory.
 *
 * @param {string} file - path to file relative to test data directory
 * @returns {Promise<string>}
 */
export async function readTextFile(file) {
	if (isNodeJs()) {
		const fs = require('fs');
		const path = require('path');
		const filePath = path.join(__dirname, `../data/${file}`);

		return new Promise((resolve, reject) => {
			fs.readFile(filePath, { encoding: 'utf-8' }, (err, data) => {
				if (err) {
					reject(err);
					return;
				}
				resolve(data);
			});
		});
	}

	const req = new Request(`../data/${file}`);
	const response = await fetch(req);
	const text = await response.text();
	return text;
}
