/**
 * Copyright (c) 2020-2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

/**
 * @returns {boolean}
 */
function isNodeJs() {
	return globalThis.window === undefined;
}

let rootDirPath = "";
/**
 * Get the path to the root directory of this repository in NodeJS.
 *
 * @returns {Promise<string>}
 */
async function rootDir() {
	if (rootDirPath) {
		return rootDirPath;
	}
	const { default: path } = await import("node:path");
	const { fileURLToPath } = await import("node:url");

	const __filename = fileURLToPath(import.meta.url);
	const __dirname = path.dirname(__filename);
	// eslint-disable-next-line require-atomic-updates
	rootDirPath = path.resolve(path.join(__dirname, "../../"));
	return rootDirPath;
}

/**
 * Read a file with the requested encoding from the root directory.
 *
 * @param {string} file - path to file relative to root directory
 * @param {"utf8"|"binary"} encoding - encoding
 * @returns {Promise<string>}
 */
async function readFile(file, encoding) {
	if (isNodeJs()) {
		const fs = await import("node:fs");
		const { default: path } = await import("node:path");

		const filePath = path.join(await rootDir(), file);

		return new Promise((resolve, reject) => {
			fs.readFile(filePath, { encoding }, (err, data) => {
				if (err) {
					reject(err);
					return;
				}
				resolve(data);
			});
		});
	}

	const req = new Request(`../../${file}`);
	const response = await fetch(req);
	switch (encoding) {
		case "utf8": {
			const text = await response.text();
			return text;
		}
		case "binary": {
			const data = await response.arrayBuffer();
			const dataArray = new Uint8Array(data);
			return String.fromCodePoint(...dataArray);
		}
		default: {
			throw new Error(`unsupported encoding ${encoding}`);
		}
	}
}

/**
 * @template T
 * @param {T} val
 * @returns {T}
 */
export function deepCopy(val) {
	return structuredClone(val);
}

/**
 * Read a text file from the root directory.
 *
 * @param {string} file - path to file relative to root directory
 * @returns {Promise<string>}
 */
export function readTextFile(file) {
	return readFile(file, "utf8");
}

/**
 * Read a file as a binary string from the test data directory.
 *
 * @param {string} file - path to file relative to test data directory
 * @returns {Promise<string>} - (binary string)
 */
export function readTestFile(file) {
	return readFile(`test/data/${file}`, "binary");
}
