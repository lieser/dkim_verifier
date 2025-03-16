/**
 * Setup the global browser object and the extensionUtils module for the tests
 * environment.
 *
 * Copyright (c) 2020-2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable require-await */

import { deepCopy, readTextFile } from "./testUtils.mjs.js";
import ExtensionUtils from "../../modules/extensionUtils.mjs.js";
import sinon from "./sinonUtils.mjs.js";
import { stringEndsWith } from "../../modules/utils.mjs.js";

/**
 * Parse a JSON file that contains comments in the form of "//…".
 *
 * @param {string} data
 * @returns {any}
 */
function jsonParse(data) {
	const dataWithoutComments = data.
		split("\n").
		filter(line => !line.trimStart().startsWith("//")).
		join("\n");
	return JSON.parse(dataWithoutComments);
}

/**
 * Similar helper as sinon.fake.resolves, but without it being a spy.
 *
 * @template T
 * @param {T} val
 * @returns {() => Promise<T>}
 */
function resolves(val) {
	return () => Promise.resolve(val);
}

const messages = jsonParse(await readTextFile("_locales/en_US/messages.json"));
class FakeI18n {
	/**
	 * @returns {browser.i18n}
	 */
	static create() {
		return new FakeI18n();
	}

	getAcceptLanguages = sinon.fake.throws("No fake for browser.i18n.getAcceptLanguages!");

	/** @type {browser.i18n.getMessage} */
	getMessage(messageName, substitutions) {
		if (!(messageName in messages)) {
			return "";
		}
		let message = messages[messageName].message;
		if (typeof substitutions === "string") {
			// eslint-disable-next-line no-param-reassign
			substitutions = [substitutions];
		}
		if (Array.isArray(substitutions)) {
			for (let i = 0; i < substitutions.length; ++i) {
				message = message.replace(`$${i + 1}`, substitutions[i]);
			}
		}
		return message;
	}

	getUILanguage = sinon.fake.throws("No fake for browser.i18n.getUILanguage!");

	detectLanguage = sinon.fake.throws("No fake for browser.i18n.detectLanguage!");
}

class FakeRuntime {
	/** @type {browser.runtime.getURL} */
	getURL(path) {
		const mozExtProtocol = "moz-extension:";
		if (path.startsWith("//")) {
			return `${mozExtProtocol}${path}`;
		}
		if (path.startsWith("/")) {
			return `${mozExtProtocol}//fake${path}`;
		}
		return `${mozExtProtocol}//fake/${path}`;
	}

	/** @type {browser.runtime.sendMessage} */
	sendMessage = resolves(undefined);
}

class FakeStorageArea {
	/**
	 * @returns {browser.storage.StorageArea}
	 */
	static create() {
		return new FakeStorageArea();
	}

	/** @type {{[key: string]: any}} */
	#storage = {};

	/** @type {browser.storage.StorageArea["get"]} */
	async get(keys) {
		if (keys === null || keys === undefined) {
			return deepCopy(this.#storage);
		}

		if (typeof keys === "string") {
			// eslint-disable-next-line no-param-reassign
			keys = [keys];
		}

		/** @type {{[key: string]: string}} */
		const result = {};

		if (Array.isArray(keys)) {
			keys.forEach((key) => {
				if (key in this.#storage) {
					result[key] = deepCopy(this.#storage[key]);
				}
			});
			return result;
		} else if (typeof keys === "object") {
			Object.keys(keys).forEach((key) => {
				if (key in this.#storage) {
					result[key] = deepCopy(this.#storage[key]);
				} else {
					result[key] = deepCopy(keys[key]);
				}
			});
			return result;
		}

		throw new Error("invalid keys");
	}

	/** @type {browser.storage.StorageArea["set"]} */
	async set(keys) {
		if (typeof keys === "object") {
			/** @type {{[prefName: string]: browser.storage.StorageChange}} */
			const changes = {};
			Object.keys(keys).forEach((key) => {
				changes[key] = {
					oldValue: deepCopy(this.#storage[key]),
					newValue: deepCopy(keys[key]),
				};
				this.#storage[key] = deepCopy(keys[key]);
			});
			this.onChanged.addListener.yield(changes);
			return;
		}

		throw new Error("invalid keys");
	}

	/** @type {browser.storage.StorageArea["remove"]} */
	async remove(keys) {
		if (typeof keys === "string") {
			// eslint-disable-next-line no-param-reassign
			keys = [keys];
		}

		if (Array.isArray(keys)) {
			keys.forEach((key) => {
				delete this.#storage[key];
			});
			return;
		}

		throw new Error("invalid keys");
	}

	/** @type {browser.storage.StorageArea["clear"]} */
	async clear() {
		this.#storage = {};
	}

	onChanged = {
		addListener: sinon.stub(),
		removeListener: sinon.stub(),
		hasListener: sinon.stub(),
	};
}

class FakeStorage {
	/**
	 * @returns {browser.storage}
	 */
	static create() {
		return new FakeStorage();
	}

	local = new FakeStorageArea();
	managed = new FakeStorageArea();
	session = new FakeStorageArea();

	sync = {
		get: sinon.fake.throws("No fake for browser.storage.sync.get!"),
		getBytesInUse: sinon.fake.throws("No fake for browser.storage.sync.getBytesInUse!"),
		set: sinon.fake.throws("No fake for browser.storage.sync.set!"),
		remove: sinon.fake.throws("No fake for browser.storage.sync.remove!"),
		clear: sinon.fake.throws("No fake for browser.storage.sync.clear!"),

		onChanged: {
			addListener: sinon.stub,
			removeListener: sinon.stub,
			hasListener: sinon.stub,
		},
	};

	onChanged = {
		addListener: sinon.stub(),
		removeListener: sinon.stub(),
		hasListener: sinon.stub(),
	};

	constructor() {
		this.local.onChanged.addListener(
			/** @type {(changes: any) => void} */
			(changes) => { this.onChanged.addListener.yield(changes, "local"); });
		this.managed.onChanged.addListener(
			/** @type {(changes: any) => void} */
			(changes) => { this.onChanged.addListener.yield(changes, "managed"); });
	}
}

class FakeAccounts {
	/**
	 * @returns {browser.accounts}
	 */
	static create() {
		return new FakeAccounts();
	}

	list = resolves([]);
	get = resolves(null);
	getDefault = sinon.fake.throws("No fake for browser.accounts.getDefault!");
	setDefaultIdentity = sinon.fake.throws("No fake for browser.accounts.setDefaultIdentity!");
	getDefaultIdentity = sinon.fake.throws("No fake for browser.accounts.getDefaultIdentity!");

	onCreated = {
		addListener: sinon.fake.throws("No fake for browser.accounts.onCreated.addListener!"),
		removeListener: sinon.fake.throws("No fake for browser.accounts.onCreated.removeListener!"),
		hasListener: sinon.fake.throws("No fake for browser.accounts.onCreated.hasListener!"),
	};

	onDeleted = {
		addListener: sinon.fake.throws("No fake for browser.accounts.onDeleted.addListener!"),
		removeListener: sinon.fake.throws("No fake for browser.accounts.onDeleted.removeListener!"),
		hasListener: sinon.fake.throws("No fake for browser.accounts.onDeleted.hasListener!"),
	};

	onUpdated = {
		addListener: sinon.fake.throws("No fake for browser.accounts.onUpdated.addListener!"),
		removeListener: sinon.fake.throws("No fake for browser.accounts.onUpdated.removeListener!"),
		hasListener: sinon.fake.throws("No fake for browser.accounts.onUpdated.hasListener!"),
	};
}

class FakeMailUtils {
	/**
	 * @returns {browser.mailUtils}
	 */
	static create() {
		return new FakeMailUtils();
	}

	/**
	 * Returns the base domain for an e-mail address.
	 *
	 * @param {string} addr
	 * @returns {Promise<string>}
	 */
	getBaseDomainFromAddr(addr) {
		const publicSuffixList = [
			"co.uk",
		];
		let numberDomainParts = 2;
		if (publicSuffixList.some(suffix => stringEndsWith(addr, suffix))) {
			numberDomainParts = 3;
		}
		const fullDomain = addr.substr(addr.lastIndexOf("@") + 1);
		const domainParts = fullDomain.split(".");
		const baseDomain = domainParts.slice(-numberDomainParts).join(".");
		return Promise.resolve(baseDomain);
	}
}

export const fakeBrowser = {
	i18n: new FakeI18n(),
	runtime: new FakeRuntime(),
	storage: new FakeStorage(),
	// Thunderbird specific
	accounts: new FakeAccounts(),
	messages: {},
	// Experiments
	mailUtils: new FakeMailUtils(),
};

/**
 * Use an init function to avoid changing the type of the globals.
 */
function init() {
	// @ts-expect-error
	globalThis.browser = fakeBrowser;
	ExtensionUtils.readFile = readTextFile;
}

init();
