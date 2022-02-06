/**
 * General utility functions that do not have any dependencies.
 *
 * Copyright (c) 2013-2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env shared-node-browser */
/* eslint-disable no-use-before-define */

/**
 * Deferred Promise
 *
 * @template T
 */
export class Deferred {
	constructor() {
		/** @type {Promise<T>} */
		this.promise = new Promise((resolve, reject) => {
			/** @type {(reason: T) => void} */
			this.resolve = resolve;
			/** @type {(reason: any) => void} */
			this.reject = reject;
		});
	}
}

/**
 * Returns true if e-mail address is from domain or a subdomain of it.
 *
 * @param {string} addr
 * @param {string} domain
 * @returns {boolean}
 */
export function addrIsInDomain(addr, domain) {
	return stringEndsWith(addr, `@${domain}`) ||
		stringEndsWith(addr, `.${domain}`);
}

/**
 * Returns true if e-mail address is from the domain or a subdomain of it or if
 * the domain is a subdomain of the e-mail address.
 *
 * @param {string} addr
 * @param {string} domain
 * @returns {boolean}
 */
export function addrIsInDomain2(addr, domain) {
	return stringEndsWith(addr, `@${domain}`) ||
		stringEndsWith(addr, `.${domain}`) ||
		stringEndsWith(domain, `.${getDomainFromAddr(addr)}`);
}

/**
 * Deep copy an object. Only works with basic types.
 *
 * @template T
 * @param {T} src
 * @returns {T}
 */
export function copy(src) {
	return JSON.parse(JSON.stringify(src));
}

/**
 * Get the date as a string in the form of `YYYY-MM-DD`
 *
 * @param {Date} date
 * @returns {string}
 */
export function dateToString(date) {
	return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

/**
 * Returns true if domain1 is the same or a subdomain of domain2.
 *
 * @param {string} domain1
 * @param {string} domain2
 * @returns {boolean}
 */
export function domainIsInDomain(domain1, domain2) {
	return stringEqual(domain1, domain2) ||
		stringEndsWith(domain1, `.${domain2}`);
}

/**
 * Returns the full domain for an e-mail address.
 *
 * @param {string} addr
 * @returns {string}
 */
export function getDomainFromAddr(addr) {
	return addr.substr(addr.lastIndexOf("@") + 1);
}

/**
 * Create a promise that rejects in <ms> milliseconds.
 *
 * @template T
 * @param {number} ms
 * @param {Promise<T>} promise
 * @returns {Promise<T>}
 */
export async function promiseWithTimeout(ms, promise) {
	let timeoutId;
	const timeout = new Promise((_resolve, reject) => {
		timeoutId = setTimeout(() => {
			reject(new Error(`Timed out after ${ms} ms.`));
		}, ms);
	});

	await Promise.race([
		promise,
		timeout
	]);
	clearTimeout(timeoutId);
	return promise;
}

/**
 * Sleep for <ms> milliseconds.
 *
 * @param {number} ms
 * @returns {Promise<void>}
 */
export function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Returns true if str ends with x.
 * Comparison is done case insensitive.
 *
 * @param {string} str
 * @param {string} x
 * @returns {boolean}
 */
export function stringEndsWith(str, x) {
	const index = str.toLowerCase().lastIndexOf(x.toLowerCase());
	return index >= 0 && index === str.length - x.length;
}

/**
 * Returns true if str1 is equal str2.
 * Comparison is done case insensitive.
 *
 * @param {string} str1
 * @param {string} str2
 * @returns {boolean}
 */
export function stringEqual(str1, str2) {
	return str1.toLowerCase() === str2.toLowerCase();
}

/**
 * Get the type an object as a string.
 *
 * From https://javascriptweblog.wordpress.com/2011/08/08/fixing-the-javascript-typeof-operator/.
 *
 * @param {any} obj
 * @returns {string}
 */
export function toType(obj) {
	const typeMatch = Object.prototype.toString.call(obj).match(/\s([a-zA-Z]+)/);
	if (!typeMatch || !typeMatch[1]) {
		throw new Error(`Failed to get type for ${obj}`);
	}
	return typeMatch[1];
}
