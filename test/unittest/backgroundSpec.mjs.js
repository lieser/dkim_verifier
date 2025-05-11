/**
 * Copyright (c) 2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import "../../content/background.mjs.js";
import { FakeMessageHeader, fakeBrowser } from "../helpers/initWebExtensions.mjs.js";
import SignRules from "../../modules/dkim/signRules.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import prefs from "../../modules/preferences.mjs.js";
import sinon from "../helpers/sinonUtils.mjs.js";


describe("background [unittest]", function () {
	before(function () {
		globalThis.addEventListener = sinon.spy();
	});

	beforeEach(function () {
		// @ts-expect-error
		navigator.onLine = true;
	});

	afterEach(async function () {
		await prefs.clear();
		await SignRules.clearRules();
		fakeBrowser.reset();
	});

	describe("Display message", function () {
		it("An e-mail with DKIM (SUCCESS, no warnings)", async function () {
			const msg = await fakeBrowser.messages.addMsg("rfc6376-A.2.eml");

			await prefs.setValue("showDKIMHeader", 0);
			await prefs.setValue("showDKIMFromTooltip", 0);
			let tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Valid (Signed by example.com)", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.calledOnceWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.called).to.be.false;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.called).to.be.false;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;

			fakeBrowser.dkimHeader.resetHistory();
			await prefs.setValue("showDKIMHeader", 10);
			await prefs.setValue("showDKIMFromTooltip", 10);
			await prefs.setValue("colorFrom", true);
			tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Valid (Signed by example.com)", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.calledOnceWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.calledOnceWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.calledOnceWithExactly(tab.id, msg.id, "windowtext", "rgba(0,255,0,0.5)")).to.be.true;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;
		});

		it("An e-mail with DKIM (TEMPFAIL)", async function () {
			const msg = await fakeBrowser.messages.addMsg("rfc6376-A.2.eml");
			// @ts-expect-error
			navigator.onLine = false;

			await prefs.setValue("showDKIMHeader", 10);
			await prefs.setValue("showDKIMFromTooltip", 10);
			let tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Failed to make DNS query because Thunderbird is in offline mode.", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.calledOnceWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.callCount).to.be.eq(2);
			expect(fakeBrowser.dkimHeader.showFromTooltip.firstCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.lastCall.calledWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.called).to.be.false;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;

			fakeBrowser.dkimHeader.resetHistory();
			await prefs.setValue("showDKIMHeader", 20);
			await prefs.setValue("showDKIMFromTooltip", 20);
			await prefs.setValue("colorFrom", true);
			tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Failed to make DNS query because Thunderbird is in offline mode.", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.calledOnceWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.calledOnceWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.calledOnceWithExactly(tab.id, msg.id, "unset", "unset")).to.be.true;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;
		});

		it("An e-mail with DKIM (PERMFAIL)", async function () {
			const msg = await fakeBrowser.messages.addMsg("rfc6376-A.2.eml");
			await prefs.setValue("policy.signRules.enable", true);
			await SignRules.addRule("example.com", null, "*", "foo.com", SignRules.TYPE.ALL);

			await prefs.setValue("showDKIMHeader", 20);
			await prefs.setValue("showDKIMFromTooltip", 20);
			let tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Invalid (Wrong signer (should be foo.com))", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.calledOnceWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.callCount).to.be.eq(2);
			expect(fakeBrowser.dkimHeader.showFromTooltip.firstCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.lastCall.calledWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.called).to.be.false;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;

			fakeBrowser.dkimHeader.resetHistory();
			await prefs.setValue("showDKIMHeader", 30);
			await prefs.setValue("showDKIMFromTooltip", 30);
			await prefs.setValue("colorFrom", true);
			tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Invalid (Wrong signer (should be foo.com))", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.callCount).to.be.eq(2);
			expect(fakeBrowser.dkimHeader.showDkimHeader.firstCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.lastCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.calledOnceWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.calledOnceWithExactly(tab.id, msg.id, "windowtext", "rgba(255,0,0,0.5)")).to.be.true;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;
		});

		it("An e-mail with DKIM (PERMFAIL hidden)", async function () {
			const msg = await fakeBrowser.messages.addMsg("rfc6376-A.2.eml");
			await prefs.setValue("policy.signRules.enable", true);
			await SignRules.addRule("example.com", null, "*", "foo.com", SignRules.TYPE.HIDEFAIL);

			await prefs.setValue("showDKIMHeader", 30);
			await prefs.setValue("showDKIMFromTooltip", 30);
			let tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Invalid (Wrong signer (should be foo.com))", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.callCount).to.be.eq(2);
			expect(fakeBrowser.dkimHeader.showDkimHeader.firstCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.lastCall.calledWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.callCount).to.be.eq(2);
			expect(fakeBrowser.dkimHeader.showFromTooltip.firstCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.lastCall.calledWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.called).to.be.false;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;

			fakeBrowser.dkimHeader.resetHistory();
			await prefs.setValue("showDKIMHeader", 40);
			await prefs.setValue("showDKIMFromTooltip", 40);
			await prefs.setValue("colorFrom", true);
			tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Invalid (Wrong signer (should be foo.com))", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.callCount).to.be.eq(2);
			expect(fakeBrowser.dkimHeader.showDkimHeader.firstCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.lastCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.calledOnceWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.calledOnceWithExactly(tab.id, msg.id, "unset", "unset")).to.be.true;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;
		});

		it("An e-mail without DKIM", async function () {
			const msg = await fakeBrowser.messages.addMsg("fakePayPal.eml");

			await prefs.setValue("showDKIMHeader", 30);
			await prefs.setValue("showDKIMFromTooltip", 30);
			let tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "No Signature", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.calledOnceWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.callCount).to.be.eq(2);
			expect(fakeBrowser.dkimHeader.showFromTooltip.firstCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.lastCall.calledWithExactly(tab.id, msg.id, false)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.called).to.be.false;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;

			fakeBrowser.dkimHeader.resetHistory();
			await prefs.setValue("showDKIMHeader", 40);
			await prefs.setValue("showDKIMFromTooltip", 40);
			await prefs.setValue("colorFrom", true);
			tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "No Signature", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.callCount).to.be.eq(2);
			expect(fakeBrowser.dkimHeader.showDkimHeader.firstCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.lastCall.calledWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.calledOnceWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.calledOnceWithExactly(tab.id, msg.id, "unset", "unset")).to.be.true;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;
		});

		it("A message that does not exist", async function () {
			const msg = new FakeMessageHeader();
			const tab = await fakeBrowser.displayMsg(msg);
			expect(fakeBrowser.dkimHeader.setDkimHeaderResult.calledOnceWithExactly(tab.id, msg.id, "Internal error", [], "", {})).to.be.true;
			expect(fakeBrowser.dkimHeader.showDkimHeader.calledOnceWithExactly(tab.id, msg.id, true)).to.be.true;
			expect(fakeBrowser.dkimHeader.showFromTooltip.called).to.be.false;
			expect(fakeBrowser.dkimHeader.highlightFromAddress.called).to.be.false;
			expect(fakeBrowser.dkimHeader.reset.called).to.be.false;
		});
	});
});
