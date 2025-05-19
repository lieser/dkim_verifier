/**
 * Copyright (c) 2020-2021;2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import "../helpers/initWebExtensions.mjs.js";
import ExtensionUtils from "../../modules/extensionUtils.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import sinon from "../helpers/sinonUtils.mjs.js";

describe("ExtensionUtils [unittest]", function () {
	describe("isOutgoing", function () {
		afterEach(function () {
			sinon.restore();
		});

		/**
		 * @param {string} accountId
		 * @param {browser.folders.MailFolderSpecialUse} [folderType]
		 * @returns {browser.messages.MessageHeader}
		 */
		function createFakeMessageHeader(accountId, folderType) {
			return {
				author: "from@example.com",
				bccList: [],
				ccList: [],
				date: new Date(),
				external: false,
				flagged: false,
				folder: { accountId, path: "", type: folderType },
				headerMessageId: "",
				headersOnly: false,
				id: 42,
				junk: false,
				junkScore: 0,
				read: true,
				new: false,
				recipients: ["to@example.com"],
				size: 42,
				subject: "A fake message",
				tags: [],
			};
		}

		it("based on folder type", async function () {
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", undefined), "foo@example.com")
			).to.be.equal(false);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", "inbox"), "foo@example.com")
			).to.be.equal(false);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", "trash"), "foo@example.com")
			).to.be.equal(false);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", "archives"), "foo@example.com")
			).to.be.equal(false);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", "junk"), "foo@example.com")
			).to.be.equal(false);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", "drafts"), "foo@example.com")
			).to.be.equal(true);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", "sent"), "foo@example.com")
			).to.be.equal(true);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", "templates"), "foo@example.com")
			).to.be.equal(true);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", "outbox"), "foo@example.com")
			).to.be.equal(true);
		});

		it("based on identity", async function () {
			const browserAccountsGet = sinon.stub(browser.accounts, "get");
			// eslint-disable-next-line require-await
			browserAccountsGet.callsFake(async (accountId) => {
				if (accountId !== "fakeAccount") {
					return null;
				}
				return {
					id: accountId,
					identities: [
						{ email: "bar@test.com" },
						{ email: "foo@example.com" },
					],
					name: "A fake account",
					type: "imap",
				};
			});

			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", undefined), "bar@example.com")
			).to.be.equal(false);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", undefined), "bar@test.com")
			).to.be.equal(true);
			expect(
				await ExtensionUtils.isOutgoing(createFakeMessageHeader("fakeAccount", undefined), "foo@example.com")
			).to.be.equal(true);
		});
	});
});
