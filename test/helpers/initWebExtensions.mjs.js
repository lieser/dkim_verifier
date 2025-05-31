/**
 * Setup the global browser object and the extensionUtils module for the tests
 * environment.
 *
 * Note that the mostly unused static create() functions are for type checking.
 *
 * Copyright (c) 2020-2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable no-magic-numbers */
/* eslint-disable require-await */

import { deepCopy, readTestFile, readTextFile } from "./testUtils.mjs.js";
import ExtensionUtils from "../../modules/extensionUtils.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import { queryDnsTxt } from "./dnsStub.mjs.js";
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

class FakeWebExtEvent {
	addListener = sinon.stub();
	removeListener = sinon.stub();
	hasListener = sinon.stub();
}

class FakeWebExtEventThatThrows {
	/**
	 * @param {string} name
	 */
	constructor(name) {
		this.addListener = sinon.fake.throws(`No fake for ${name}.addListener!`);
		this.removeListener = sinon.fake.throws(`No fake for ${name}.removeListener!`);
		this.hasListener = sinon.fake.throws(`No fake for ${name}.hasListener!`);
	}
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
			for (const [i, substitution] of substitutions.entries()) {
				message = message.replace(`$${i + 1}`, substitution);
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

	/** @type {browser.runtime.onMessage} */
	onMessage = new FakeWebExtEvent();
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
			for (const key of keys) {
				if (key in this.#storage) {
					result[key] = deepCopy(this.#storage[key]);
				}
			}
			return result;
		} else if (typeof keys === "object") {
			for (const key of Object.keys(keys)) {
				result[key] = key in this.#storage ? deepCopy(this.#storage[key]) : deepCopy(keys[key]);
			}
			return result;
		}

		throw new Error("invalid keys");
	}

	/** @type {browser.storage.StorageArea["set"]} */
	async set(keys) {
		if (typeof keys === "object") {
			/** @type {{[prefName: string]: browser.storage.StorageChange}} */
			const changes = {};
			for (const key of Object.keys(keys)) {
				changes[key] = {
					oldValue: deepCopy(this.#storage[key]),
					newValue: deepCopy(keys[key]),
				};
				this.#storage[key] = deepCopy(keys[key]);
			}
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
			for (const key of keys) {
				delete this.#storage[key];
			}
			return;
		}

		throw new Error("invalid keys");
	}

	/** @type {browser.storage.StorageArea["clear"]} */
	async clear() {
		this.#storage = {};
	}

	onChanged = new FakeWebExtEvent();
}

class FakeStorage {
	/**
	 * @returns {browser.storage}
	 */
	static create() {
		return new FakeStorage();
	}

	constructor() {
		this.local.onChanged.addListener(
			/** @type {(changes: any) => void} */
			(changes) => { this.onChanged.addListener.yield(changes, "local"); });
		this.managed.onChanged.addListener(
			/** @type {(changes: any) => void} */
			(changes) => { this.onChanged.addListener.yield(changes, "managed"); });
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

		onChanged: new FakeWebExtEvent(),
	};

	onChanged = new FakeWebExtEvent();
}

class FakeTab {
	/**
	 * @returns {browser.tabs.Tab}
	 */
	static create() {
		return new FakeTab();
	}

	id = 1;
	index = 0;
	highlighted = false;
	active = true;
}

class FakeTabs {
	/**
	 * @returns {browser.tabs}
	 */
	static create() {
		return new FakeTabs();
	}

	TAB_ID_NONE = -1;
	get = sinon.fake.throws("No fake for browser.tabs.get!");
	getCurrent = sinon.fake.throws("No fake for browser.tabs.getCurrent!");
	connect = sinon.fake.throws("No fake for browser.tabs.connect!");
	sendMessage = sinon.fake.throws("No fake for browser.tabs.sendMessage!");
	create = sinon.fake.throws("No fake for browser.tabs.create!");
	duplicate = sinon.fake.throws("No fake for browser.tabs.duplicate!");
	query = sinon.fake.throws("No fake for browser.tabs.query!");
	update = sinon.fake.throws("No fake for browser.tabs.update!");
	move = sinon.fake.throws("No fake for browser.tabs.move!");
	reload = sinon.fake.throws("No fake for browser.tabs.reload!");
	remove = sinon.fake.throws("No fake for browser.tabs.remove!");
	executeScript = sinon.fake.throws("No fake for browser.tabs.executeScript!");
	insertCSS = sinon.fake.throws("No fake for browser.tabs.insertCSS!");
	removeCSS = sinon.fake.throws("No fake for browser.tabs.removeCSS!");

	onCreated = new FakeWebExtEventThatThrows("browser.tabs.onCreated");
	onUpdated = new FakeWebExtEventThatThrows("browser.tabs.onUpdated");
	onMoved = new FakeWebExtEventThatThrows("browser.tabs.onMoved");
	onActivated = new FakeWebExtEventThatThrows("browser.tabs.onActivated");
	onDetached = new FakeWebExtEventThatThrows("browser.tabs.onDetached");
	onAttached = new FakeWebExtEventThatThrows("browser.tabs.onAttached");
	onRemoved = new FakeWebExtEvent();
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

	onCreated = new FakeWebExtEventThatThrows("browser.accounts.onCreated");
	onDeleted = new FakeWebExtEventThatThrows("browser.accounts.onDeleted");
	onUpdated = new FakeWebExtEventThatThrows("browser.accounts.onUpdated");
}

export class FakeMessageHeader {
	/**
	 * @returns {browser.messages.MessageHeader}
	 */
	static create() {
		return new FakeMessageHeader();
	}

	author = "from@example.com";
	/** @type {string[]} */
	bccList = [];
	/** @type {string[]} */
	ccList = [];
	date = new Date();
	external = false;
	flagged = false;

	folder = {
		accountId: "fakeAccount",
		path: "",
		/** @type {browser.folders.MailFolderSpecialUse} */
		type: "inbox",
	};

	headerMessageId = "";
	headersOnly = false;
	id = 42;
	junk = false;
	junkScore = 0;
	// read = true;
	new = false;
	recipients = ["to@example.com"];
	size = 42;
	subject = "A fake message";
	/** @type {string[]} */
	tags = [];
}

class FakeMessages {
	/**
	 * @returns {browser.messages}
	 */
	static create() {
		return new FakeMessages();
	}

	list = sinon.fake.throws("No fake for browser.messages.list!");
	continueList = sinon.fake.throws("No fake for browser.messages.continueList!");
	abortList = sinon.fake.throws("No fake for browser.messages.abortList!");
	get = sinon.fake.throws("No fake for browser.messages.get!");

	/** @type {browser.messages.getFull} */
	getFull(messageId) {
		const message = this.#messages.get(messageId);
		if (!message) {
			throw new Error("Message not found");
		}

		return Promise.resolve({
			headers: message.headers,
		});
	}

	/** @type {browser.messages.getRaw} */
	getRaw(messageId) {
		const message = this.#messages.get(messageId);
		if (!message) {
			throw new Error("Message not found");
		}

		return Promise.resolve(message.raw);
	}

	listAttachments = sinon.fake.throws("No fake for browser.messages.listAttachments!");
	getAttachmentFile = sinon.fake.throws("No fake for browser.messages.getAttachmentFile!");
	deleteAttachments = sinon.fake.throws("No fake for browser.messages.deleteAttachments!");
	openAttachment = sinon.fake.throws("No fake for browser.messages.openAttachment!");
	query = sinon.fake.throws("No fake for browser.messages.query!");
	update = sinon.fake.throws("No fake for browser.messages.update!");
	move = sinon.fake.throws("No fake for browser.messages.move!");
	copy = sinon.fake.throws("No fake for browser.messages.copy!");
	delete = sinon.fake.throws("No fake for browser.messages.delete!");
	import = sinon.fake.throws("No fake for browser.messages.import!");
	archive = sinon.fake.throws("No fake for browser.messages.archive!");
	listTags = sinon.fake.throws("No fake for browser.messages.listTags!");
	createTag = sinon.fake.throws("No fake for browser.messages.createTag!");
	updateTag = sinon.fake.throws("No fake for browser.messages.updateTag!");
	deleteTag = sinon.fake.throws("No fake for browser.messages.deleteTag!");
	onUpdated = new FakeWebExtEventThatThrows("browser.messages.onUpdated");
	onMoved = new FakeWebExtEventThatThrows("browser.messages.onMoved");
	onCopied = new FakeWebExtEventThatThrows("browser.messages.onCopied");
	onDeleted = new FakeWebExtEventThatThrows("browser.messages.onDeleted");
	onNewMailReceived = new FakeWebExtEventThatThrows("browser.messages.onNewMailReceived");

	tags = {
		list: sinon.fake.throws("No fake for browser.messages.tags.list!"),
		create: sinon.fake.throws("No fake for browser.messages.tags.create!"),
		update: sinon.fake.throws("No fake for browser.messages.tags.update!"),
		delete: sinon.fake.throws("No fake for browser.messages.tags.delete!"),
	};

	#lastMsgId = 0;
	/** @type {Map.<number, {raw: string, headers: { [key: string]: string[] }}>} */
	#messages = new Map();

	/**
	 * @param {string} file - path to file relative to test data directory
	 * @returns {Promise<browser.messages.MessageHeader>}
	 */
	async addMsg(file) {
		const raw = await readTestFile(file);
		const msgParsed = MsgParser.parseMsg(raw);

		const messageHeader = new FakeMessageHeader();
		messageHeader.id = ++this.#lastMsgId;
		messageHeader.author = FakeMessages.#extractHeaderValue(msgParsed.headers, "from")[0] ?? "";
		messageHeader.recipients = FakeMessages.#extractHeaderValue(msgParsed.headers, "to");
		messageHeader.subject = FakeMessages.#extractHeaderValue(msgParsed.headers, "subject")[0] ?? "";

		this.#messages.set(messageHeader.id, {
			raw,
			headers: Object.fromEntries(msgParsed.headers.entries()),
		});

		return messageHeader;
	}

	/**
	 * @param {Map<string, string[]>} headers
	 * @param {string} name
	 * @returns {string[]}
	 */
	static #extractHeaderValue(headers, name) {
		const completeHeaders = headers.get(name);
		if (completeHeaders === undefined) {
			return [];
		}
		return completeHeaders.map(header =>
			header.slice(name.length + ": ".length).slice(0, -"\r\n".length));
	}
}

class FakeMessageDisplay {
	/**
	 * @returns {browser.messageDisplay}
	 */
	static create() {
		return new FakeMessageDisplay();
	}

	getDisplayedMessage = sinon.fake.throws("No fake for browser.messageDisplay.getDisplayedMessage!");
	getDisplayedMessages = sinon.fake.throws("No fake for browser.messageDisplay.getDisplayedMessage!");
	open = sinon.fake.throws("No fake for browser.messageDisplay.open!");

	onMessageDisplayed = new FakeWebExtEvent();
	onMessagesDisplayed = new FakeWebExtEvent();
}

class FakeDkimHeader {
	/**
	 * @returns {browser.dkimHeader}
	 */
	static create() {
		return new FakeDkimHeader();
	}

	showDkimHeader = sinon.spy();
	showFromTooltip = sinon.spy();
	setDkimHeaderResult = sinon.fake.resolves(true);
	highlightFromAddress = sinon.spy();
	reset = sinon.spy();

	resetHistory() {
		this.showDkimHeader.resetHistory();
		this.showFromTooltip.resetHistory();
		this.setDkimHeaderResult.resetHistory();
		this.highlightFromAddress.resetHistory();
		this.reset.resetHistory();
	}
}

class FakeJsdns {
	/**
	 * @returns {browser.jsdns}
	 */
	static create() {
		return new FakeJsdns();
	}

	configure = sinon.spy();
	txt = queryDnsTxt;
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
		const fullDomain = addr.slice(addr.lastIndexOf("@") + 1);
		const domainParts = fullDomain.split(".");
		const baseDomain = domainParts.slice(-numberDomainParts).join(".");
		return Promise.resolve(baseDomain);
	}
}

class FakeBrowser {
	i18n = new FakeI18n();
	runtime = new FakeRuntime();
	storage = new FakeStorage();
	tabs = new FakeTabs();
	// Thunderbird specific
	accounts = new FakeAccounts();
	messages = new FakeMessages();
	messageDisplay = new FakeMessageDisplay();
	// Experiments
	dkimHeader = new FakeDkimHeader();
	jsdns = new FakeJsdns();
	mailUtils = new FakeMailUtils();

	/**
	 * @param {browser.messages.MessageHeader} msg
	 * @returns {Promise<browser.tabs.Tab>}
	 */
	async displayMsg(msg) {
		const tab = new FakeTab();
		const results = this.messageDisplay.onMessageDisplayed.addListener.yield(tab, msg);
		for (const result of results) {
			await result;
		}
		return tab;
	}

	reset() {
		this.messages = new FakeMessages();
		this.dkimHeader.resetHistory();
	}
}

export const fakeBrowser = new FakeBrowser();

/**
 * Use an init function to avoid changing the type of the globals.
 */
function init() {
	// @ts-expect-error
	globalThis.browser = fakeBrowser;
	ExtensionUtils.readFile = readTextFile;
}

init();
