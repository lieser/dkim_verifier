/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import {DKIM_InternalError} from "../../modules/error.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";

describe("Message parser [unittest]", function () {
	describe("RFC 6376 Appendix A Example", function () {
		const msgPlain =
			"DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;\r\n" +
			"      c=simple/simple; q=dns/txt; i=joe@football.example.com;\r\n" +
			"      h=Received : From : To : Subject : Date : Message-ID;\r\n" +
			"      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
			"      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\r\n" +
			"        4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut\r\n" +
			"        KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV\r\n" +
			"        4bmp/YzhwvcubU4=;\r\n" +
			"Received: from client1.football.example.com  [192.0.2.1]\r\n" +
			"      by submitserver.example.com with SUBMISSION;\r\n" +
			"      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)\r\n" +
			"From: Joe SixPack <joe@football.example.com>\r\n" +
			"To: Suzie Q <suzie@shopping.example.net>\r\n" +
			"Subject: Is dinner ready?\r\n" +
			"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
			"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n" +
			"\r\n" +
			"Hi.\r\n" +
			"\r\n" +
			"We lost the game. Are you hungry yet?\r\n" +
			"\r\n" +
			"Joe.\r\n";

		const msgBody =
			"Hi.\r\n" +
			"\r\n" +
			"We lost the game. Are you hungry yet?\r\n" +
			"\r\n" +
			"Joe.\r\n";

		it("parse CRLF", function () {
			const msg = MsgParser.parseMsg(msgPlain);
			expect(msg.body).to.be.equal(msgBody);

			expect(msg.headers.has("received")).to.be.true;
			// @ts-ignore
			expect(msg.headers.get("received").length).to.be.equal(1);

			expect(msg.headers.has("subject")).to.be.true;
			// @ts-ignore
			expect(msg.headers.get("subject").length).to.be.equal(1);
			// @ts-ignore
			expect(msg.headers.get("subject")[0]).to.be.equal("Subject: Is dinner ready?\r\n");
		});
		it("parse LF", function () {
			const msg = MsgParser.parseMsg(msgPlain.replace(/\r\n/g, "\n"));
			expect(msg.body).to.be.equal(msgBody);

			expect(msg.headers.has("subject")).to.be.true;
			// @ts-ignore
			expect(msg.headers.get("subject").length).to.be.equal(1);
			// @ts-ignore
			expect(msg.headers.get("subject")[0]).to.be.equal("Subject: Is dinner ready?\r\n");
		});
		it("parse CR", function () {
			const msg = MsgParser.parseMsg(msgPlain.replace(/\r\n/g, "\r"));
			expect(msg.body).to.be.equal(msgBody);

			expect(msg.headers.has("subject")).to.be.true;
			// @ts-ignore
			expect(msg.headers.get("subject").length).to.be.equal(1);
			// @ts-ignore
			expect(msg.headers.get("subject")[0]).to.be.equal("Subject: Is dinner ready?\r\n");
		});

		it("multiple received headers", function () {
			const msg = MsgParser.parseMsg(`Received: foo\r\n${msgPlain}`);
			expect(msg.body).to.be.equal(msgBody);

			expect(msg.headers.has("received")).to.be.true;
			// @ts-ignore
			expect(msg.headers.get("received").length).to.be.equal(2);
			// @ts-ignore
			expect(msg.headers.get("received")[0]).to.be.equal("Received: foo\r\n");
			// @ts-ignore
			expect(msg.headers.get("received")[1]).to.have.string('\r\n      by submitserver.example.com');
		});

		it("missing newline between header and body", function () {
			expect(
				() => MsgParser.parseMsg(msgPlain.replace(/\r\n\r\n/g, "\r\n"))
			).to.throw(DKIM_InternalError).with.property("errorType", "DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT");
		});
	});
	describe("Extracting address from an address-list", function () {
		it("angle-addr only", function () {
			expect(
				MsgParser.parseAddressingHeader("<foo@example.com>")
			).to.be.equal("foo@example.com");
		});
		it("name-addr with simple atoms as display-name", function () {
			expect(
				MsgParser.parseAddressingHeader("this is from foo <foo@example.com>")
			).to.be.equal("foo@example.com");
		});
		it("name-addr with simple quoted-string as display-name", function () {
			expect(
				MsgParser.parseAddressingHeader(`"this is from foo" <foo@example.com>`)
			).to.be.equal("foo@example.com");
		});
	});
});
