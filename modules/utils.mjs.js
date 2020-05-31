/*
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
/* eslint-disable no-use-before-define */

/**
 * Deferred Promise
 * @class
 * @template T
 * @property {Promise<T>} promise
 * @property {Function} resolve
 *           Function to call to resolve promise
 * @property {Function} reject
 *           Function to call to reject promise
 */
class Deferred {
	constructor() {
		this.promise = new Promise((resolve, reject) => {
			this.resolve = resolve;
			this.reject = reject;
		});
	}
}

/**
 * Returns true if e-mail address is from domain or a subdomain of it.
 *
 * @param {string} addr
 * @param {string} domain
 *
 * @return {boolean}
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
 *
 * @return {boolean}
 */
export function addrIsInDomain2(addr, domain) {
	return stringEndsWith(addr, `@${domain}`) ||
		stringEndsWith(addr, `.${domain}`) ||
		stringEndsWith(domain, `.${getDomainFromAddr(addr)}`);
}

/**
 * Returns true if domain1 is the same or a subdomain of domain2.
 *
 * @param {string} domain1
 * @param {string} domain2
 *
 * @return {boolean}
 */
export function domainIsInDomain(domain1, domain2) {
	return stringEqual(domain1, domain2) ||
		stringEndsWith(domain1, `.${domain2}`);
}

/**
 * Returns the base domain for an e-mail address; that is, the public suffix
 * with a given number of additional domain name parts.
 *
 * @param {string} addr
 * @param {number} [aAdditionalParts=0]
 *
 * @return {string}
 */
function getBaseDomainFromAddr(addr, aAdditionalParts=0) {
	// var fullDomain = addr.substr(addr.lastIndexOf("@")+1);
	var nsiURI = Services.io.newURI(`http://${addr}`, null, null);
	var res;
	try {
		res = eTLDService.getBaseDomain(nsiURI, aAdditionalParts);
	} catch (e) {
		// domains like "blogspot.co.uk", "blogspot.com", "googlecode.com"
		// are on the public suffix list, but should be valid base domains
		// because e-mails may be send from them
		if (e.result === Cr.NS_ERROR_INSUFFICIENT_DOMAIN_LEVELS && aAdditionalParts === 0) {
			// add "invalid" subdomain to avoid error
			let invalidSub = "invalid.";
			var host = invalidSub + nsiURI.asciiHost;
			res = eTLDService.getBaseDomainFromHost(host, 0);
			// remove "invalid" subdomain from result
			res = res.substr(invalidSub.length);
		}
	}
	return res;
}

/**
 * Returns the full domain for an e-mail address
 *
 * @param {string} addr
 *
 * @return {string}
 */
export function getDomainFromAddr(addr) {
	return addr.substr(addr.lastIndexOf("@")+1);
}

/**
 * Returns true if str ends with x.
 * Comparison is done case insensitive.
 *
 * @param {string} str
 * @param {string} x
 *
 * @return {boolean}
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
 *
 * @return {boolean}
 */
export function stringEqual(str1, str2) {
	return str1.toLowerCase() === str2.toLowerCase();
}

/**
 * Get the type an object as a string.
 *
 * From https://javascriptweblog.wordpress.com/2011/08/08/fixing-the-javascript-typeof-operator/
 *
 * @param {any} obj
 *
 * @return {string}
 */
export function toType(obj) {
	const typeMatch = Object.prototype.toString.call(obj).match(/\s([a-zA-Z]+)/);
	if (!typeMatch) {
		throw new Error(`Failed to get type for ${obj}`);
	}
	return typeMatch[1];
}
