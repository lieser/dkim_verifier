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

let rootDirPath = "";
async function rootDir() {
	if (rootDirPath) {
		return rootDirPath;
	}
	const path = await import("path");
	const { fileURLToPath } = await import("url");

	const __filename = fileURLToPath(import.meta.url);
	const __dirname = path.dirname(__filename);
	rootDirPath = path.resolve(path.join(__dirname, "../../"));
	return rootDirPath;
}

/**
 * Read a text file from the test data directory.
 *
 * @param {string} file - path to file relative to test data directory
 * @returns {Promise<string>}
 */
export async function readTextFile(file) {
	if (isNodeJs()) {
		const fs = await import("fs");
		const path = await import("path");

		const filePath = path.join(await rootDir(), `test/data/${file}`);

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
