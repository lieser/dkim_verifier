/**
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import { DKIM_InternalError } from "../../modules/error.mjs.js";
import MsgParser from "../../modules/msgParser.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { toBinaryString } from "../helpers/testUtils.mjs.js";

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
			expect(msg.headers.size).to.be.equal(7);

			expect(msg.headers.has("received")).to.be.true;
			// @ts-expect-error
			expect(msg.headers.get("received").length).to.be.equal(1);

			expect(msg.headers.has("subject")).to.be.true;
			// @ts-expect-error
			expect(msg.headers.get("subject").length).to.be.equal(1);
			// @ts-expect-error
			expect(msg.headers.get("subject")[0]).to.be.equal("Subject: Is dinner ready?\r\n");
		});
		it("parse LF", function () {
			const msg = MsgParser.parseMsg(msgPlain.replace(/\r\n/g, "\n"));
			expect(msg.body).to.be.equal(msgBody);
			expect(msg.headers.size).to.be.equal(7);

			expect(msg.headers.has("subject")).to.be.true;
			// @ts-expect-error
			expect(msg.headers.get("subject").length).to.be.equal(1);
			// @ts-expect-error
			expect(msg.headers.get("subject")[0]).to.be.equal("Subject: Is dinner ready?\r\n");
		});
		it("parse CR", function () {
			const msg = MsgParser.parseMsg(msgPlain.replace(/\r\n/g, "\r"));
			expect(msg.body).to.be.equal(msgBody);
			expect(msg.headers.size).to.be.equal(7);

			expect(msg.headers.has("subject")).to.be.true;
			// @ts-expect-error
			expect(msg.headers.get("subject").length).to.be.equal(1);
			// @ts-expect-error
			expect(msg.headers.get("subject")[0]).to.be.equal("Subject: Is dinner ready?\r\n");
		});

		it("multiple received headers", function () {
			const msg = MsgParser.parseMsg(`Received: foo\r\n${msgPlain}`);
			expect(msg.body).to.be.equal(msgBody);
			expect(msg.headers.size).to.be.equal(7);

			expect(msg.headers.has("received")).to.be.true;
			// @ts-expect-error
			expect(msg.headers.get("received").length).to.be.equal(2);
			// @ts-expect-error
			expect(msg.headers.get("received")[0]).to.be.equal("Received: foo\r\n");
			// @ts-expect-error
			expect(msg.headers.get("received")[1]).to.have.string("\r\n      by submitserver.example.com");
		});

		it("missing newline between header and body", function () {
			expect(
				() => MsgParser.parseMsg(msgPlain.replace(/\r\n\r\n/g, "\r\n"))
			).to.throw(DKIM_InternalError).with.property("errorType", "DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT");
		});
		it("Valid missing body", function () {
			let msg = MsgParser.parseMsg(msgPlain.replace(/\r\n\r\n.+/gs, "\r\n"));
			expect(msg.body).to.be.equal("");
			expect(msg.headers.size).to.be.equal(7);
			msg = MsgParser.parseMsg(msgPlain.replace(/\r\n\r\n.+/gs, "\n"));
			expect(msg.body).to.be.equal("");
			expect(msg.headers.size).to.be.equal(7);
			msg = MsgParser.parseMsg(msgPlain.replace(/\r\n\r\n.+/gs, "\r"));
			expect(msg.body).to.be.equal("");
			expect(msg.headers.size).to.be.equal(7);
		});
		it("With a missing body the headers still need to end with a newline", function () {
			expect(
				() => MsgParser.parseMsg(msgPlain.replace(/\r\n\r\n.+/gs, ""))
			).to.throw(DKIM_InternalError).with.property("errorType", "DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT");
		});
		it("Valid empty body", function () {
			const msg = MsgParser.parseMsg(msgPlain.replace(/\r\n\r\n.+/gs, "\r\n\r\n"));
			expect(msg.body).to.be.equal("");
			expect(msg.headers.size).to.be.equal(7);
		});
	});
	describe("Extracting From address", function () {
		describe("addr-spec", function () {
			it("without comment", function () {
				expect(
					MsgParser.parseFromHeader("From: foo@example.com\r\n")
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader("From:  foo@example.com \r\n")
				).to.be.equal("foo@example.com");
			});
			it("with comment", function () {
				expect(
					MsgParser.parseFromHeader("From: (comment) foo@example.com\r\n")
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader("From: (bar@bad.com) foo@example.com\r\n")
				).to.be.equal("foo@example.com");
			});
			it("with quoted-string as local part", function () {
				expect(
					MsgParser.parseFromHeader('From: "foo bar"@example.com\r\n')
				).to.be.equal('"foo bar"@example.com');
			});
		});
		describe("name-addr", function () {
			it("angle-addr only", function () {
				expect(
					MsgParser.parseFromHeader("From: <foo@example.com>\r\n")
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader("From:   <foo@example.com>\t\r\n")
				).to.be.equal("foo@example.com");
			});
			it("with simple atoms as display-name", function () {
				expect(
					MsgParser.parseFromHeader("From: singleAtom <foo@example.com>\r\n")
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader("From: this is from foo <foo@example.com>\r\n")
				).to.be.equal("foo@example.com");
			});
			it("with simple quoted-string as display-name", function () {
				expect(
					MsgParser.parseFromHeader("From: \"this is from foo\" <foo@example.com>\r\n")
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader("From: \"bar@bad.com\" <foo@example.com>\r\n")
				).to.be.equal("foo@example.com");
			});
			it("with comment", function () {
				expect(
					MsgParser.parseFromHeader("From: (bar@bad.com) <foo@example.com>\r\n")
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader("From: A (bar@bad.com) comment <foo@example.com>\r\n")
				).to.be.equal("foo@example.com");
			});
			it("with quoted-string as local part", function () {
				expect(
					MsgParser.parseFromHeader('From: <"foo bar"@example.com>\r\n')
				).to.be.equal('"foo bar"@example.com');
				expect(
					MsgParser.parseFromHeader('From: "a test" <"foo@bar"@example.com>\r\n')
				).to.be.equal('"foo@bar"@example.com');
			});
			it("Strange but valid display name", function () {
				expect(
					MsgParser.parseFromHeader("From: \"mixed\" atoms \"and quoted-string\" <foo@example.com>\r\n")
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader('From: "a"strange"phrase" <foo@example.com>\r\n')
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader('From: another"strange"phrase <foo@example.com>\r\n')
				).to.be.equal("foo@example.com");
				expect(
					MsgParser.parseFromHeader('From: "multiple""quoted-string""without" space "between" <foo@example.com>\r\n')
				).to.be.equal("foo@example.com");
			});
		});
		it("Casing of From header", function () {
			expect(
				MsgParser.parseFromHeader("FROM: foo@example.com\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("from: foo@example.com\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("frOm: <foo@example.com>\r\n")
			).to.be.equal("foo@example.com");
		});
		it("RFC 5322 Appendix A", function () {
			// Appendix A.1.1.  A Message from One Person to Another with Simple
			expect(
				MsgParser.parseFromHeader("From: John Doe <jdoe@machine.example>\r\n")
			).to.be.equal("jdoe@machine.example");
			// Appendix A.1.2.  Different Types of Mailboxes
			expect(
				MsgParser.parseFromHeader('From: "Joe Q. Public" <john.q.public@example.com>\r\n')
			).to.be.equal("john.q.public@example.com");
			// Appendix A.1.3.  Group Addresses
			expect(
				MsgParser.parseFromHeader("From: Pete <pete@silly.example>\r\n")
			).to.be.equal("pete@silly.example");
			// Appendix A.2.  Reply Messages
			expect(
				MsgParser.parseFromHeader("From: Mary Smith <mary@example.net>\r\n")
			).to.be.equal("mary@example.net");
			// Appendix A.4.  Messages with Trace Fields
			expect(
				MsgParser.parseFromHeader("From: John Doe <jdoe@node.example>\r\n")
			).to.be.equal("jdoe@node.example");
			// Appendix A.5.  White Space, Comments, and Other Oddities
			expect(
				MsgParser.parseFromHeader("From: Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>\r\n")
			).to.be.equal("pete@silly.test");
			expect(
				MsgParser.parseFromHeader("From: Chris Jones <c@(Chris's host.)public.example>\r\n")
			).to.be.equal("c@public.example");
		});
		it("RFC 5322 Appendix A - Obsolete", function () {
			// Obsolete syntax is only partly supported

			// Appendix A.6.1.  Obsolete Addressing
			expect(
				MsgParser.parseFromHeader("From: Joe Q. Public <john.q.public@example.com>\r\n")
			).to.be.equal("john.q.public@example.com");
			// Appendix A.6.3.  Obsolete White Space and Comments
			expect(() =>
				MsgParser.parseFromHeader("From  : John Doe <jdoe@machine(comment).  example>\r\n")
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader("From: John Doe <jdoe@machine(comment).  example>\r\n")
			).to.throw();
		});
		it("Strange but valid whitespace", function () {
			expect(
				MsgParser.parseFromHeader("From:foo@example.com\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("From:<foo@example.com>\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("From: (\r\n some\r\n\tfolding) foo@example.com\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("From: \r\n (some\r\n\tfolding) foo@example.com\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("From: \r\n some\r\n\tfolding <foo@example.com>\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("From:\r\n   some <foo@example.com>\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("From:\r\n\t=?utf-8?q?(omit)?=\r\n\t=?utf-8?q?(omit)?= <mail@example.com>\r\n")
			).to.be.equal("mail@example.com");
		});
		it("mailbox-list", function () {
			expect(
				MsgParser.parseFromHeader("From: foo@example.com, user <user@example.com>\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("From: foo@example.com, user@example.com\r\n")
			).to.be.equal("foo@example.com");

			expect(
				MsgParser.parseFromHeader("From: foo <foo@example.com>, user@example.com\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseFromHeader("From: foo <foo@example.com>, user <user@example.com>\r\n")
			).to.be.equal("foo@example.com");

			expect(
				MsgParser.parseFromHeader("From: foo <foo@example.com>, user <user@example.com>, bar@example.com\r\n")
			).to.be.equal("foo@example.com");
		});
		it("avoid backtracking issues", function () {
			// A naive implementation of the phrase pattern can lead to backtracking issues,
			// especially if it tries but fails to match it to a long string.
			expect(
				MsgParser.parseFromHeader("From: noreply-play-developer-console@google.com\r\n")
			).to.be.equal("noreply-play-developer-console@google.com");
			expect(() =>
				MsgParser.parseFromHeader("From: noreply-play-developer-console-google.com\r\n")
			).to.throw();
		});
		it("malformed", function () {
			expect(() =>
				MsgParser.parseFromHeader("From: foo.example.com\r\n")
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader("From: <@foo.example.com>\r\n")
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader("From: bar foo@example.com\r\n")
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader("From: bar@bad.com foo@example.com\r\n")
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader("From: bar@bad.com <foo@example.com>\r\n")
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader("To: <foo@example.com>\r\n")
			).to.throw();
		});
		it("From Thunderbirds authors", function () {
			expect(
				MsgParser.parseAuthor("foo@example.com")
			).to.be.equal("foo@example.com");
		});
	});
	describe("Extracting Reply-To address", function () {
		it("Valid examples", function () {
			expect(
				MsgParser.parseReplyToHeader("Reply-To: foo@example.com\r\n")
			).to.be.equal("foo@example.com");
			expect(
				MsgParser.parseReplyToHeader('Reply-To: "noreply@mail.paypal.de" <noreply@mail.paypal.de>\r\n')
			).to.be.equal("noreply@mail.paypal.de");
		});
	});
	describe("Extracting List-Id", function () {
		it("RFC 2919 examples", function () {
			expect(
				MsgParser.parseListIdHeader("List-Id: List Header Mailing List <list-header.nisto.com>\r\n")
			).to.be.equal("list-header.nisto.com");
			expect(
				MsgParser.parseListIdHeader("List-Id: <commonspace-users.list-id.within.com>\r\n")
			).to.be.equal("commonspace-users.list-id.within.com");
			expect(
				MsgParser.parseListIdHeader("List-Id: \"Lena's Personal Joke List\"\r\n" +
					"         <lenas-jokes.da39efc25c530ad145d41b86f7420c3b.021999.localhost>\r\n")
			).to.be.equal("lenas-jokes.da39efc25c530ad145d41b86f7420c3b.021999.localhost");
			expect(
				MsgParser.parseListIdHeader('List-Id: "An internal CMU List" <0Jks9449.list-id.cmu.edu>\r\n')
			).to.be.equal("0Jks9449.list-id.cmu.edu");
			expect(
				MsgParser.parseListIdHeader("List-Id: <da39efc25c530ad145d41b86f7420c3b.052000.localhost>\r\n")
			).to.be.equal("da39efc25c530ad145d41b86f7420c3b.052000.localhost");
		});
		it("valid headers", function () {
			expect(
				MsgParser.parseListIdHeader("list-ID: <list-header.nisto.com>\r\n")
			).to.be.equal("list-header.nisto.com");
			expect(
				MsgParser.parseListIdHeader("List-Id:<list-header.nisto.com>\r\n")
			).to.be.equal("list-header.nisto.com");
			expect(
				MsgParser.parseListIdHeader('List-Id: "<fake.list.com>" <list-header.nisto.com>\r\n')
			).to.be.equal("list-header.nisto.com");
		});
		it("invalid headers", function () {
			expect(() =>
				MsgParser.parseListIdHeader("List-Id: missing-angle-brackets.example.com")
			).to.throw();
			expect(() =>
				MsgParser.parseListIdHeader("List-Id: <foo@example.com>\r\n")
			).to.throw();
			expect(() =>
				MsgParser.parseListIdHeader("List-Id: 123 <foo newsletter>\r\n")
			).to.throw();
		});
	});
	describe("Extracting the date from a Received header", function () {
		it("RFC 6376 Appendix A Example", function () {
			const received = "Received: from client1.football.example.com  [192.0.2.1]\r\n" +
				"      by submitserver.example.com with SUBMISSION;\r\n" +
				"      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)\r\n";
			expect(MsgParser.tryExtractReceivedTime(received)).
				to.be.deep.equal(new Date("2003-07-11T21:01:54.000-07:00"));
		});
		it("RFC 5322 Appendix A.4. Messages with Trace Fields", function () {
			const received = "Received: from node.example by x.y.test; 21 Nov 1997 10:01:22 -0600\r\n";
			expect(MsgParser.tryExtractReceivedTime(received)).
				to.be.deep.equal(new Date("1997-11-21T10:01:22.000-06:00"));
		});
		it("Time without seconds", function () {
			const received = "Received: from node.example by x.y.test; 21 Nov 1997 10:01 -0600\r\n";
			expect(MsgParser.tryExtractReceivedTime(received)).
				to.be.deep.equal(new Date("1997-11-21T10:01:00.000-06:00"));
		});
		it("Missing semicolon", function () {
			const received = "Received: from node.example by x.y.test 21 Nov 1997 10:01:22 -0600\r\n";
			expect(MsgParser.tryExtractReceivedTime(received)).
				to.be.null;
		});
		it("Invalid date", function () {
			const received = "Received: from node.example by x.y.test; 41 Nov 1997 10:01:22 -0600\r\n";
			expect(MsgParser.tryExtractReceivedTime(received)).
				to.be.null;
		});
	});
	describe("Internationalized Email", function () {
		it("Disabled by default", function () {
			expect(() => MsgParser.parseFromHeader(toBinaryString(
				"From: Pelé@example.com\r\n"
			))).to.throw();
			expect(() => MsgParser.parseFromHeader(toBinaryString(
				"From: <Pelé@example.com>\r\n"
			))).to.throw();
		});
		it("From header", function () {
			// https://en.wikipedia.org/wiki/E-mail_address#Internationalization_examples
			// Latin alphabet with diacritics: Pelé@example.com
			// Greek alphabet: δοκιμή@παράδειγμα.δοκιμή
			// Traditional Chinese characters: 我買@屋企.香港
			// Japanese characters: 二ノ宮@黒川.日本
			// Cyrillic characters: медведь@с-балалайкой.рф
			// Devanagari characters: संपर्क@डाटामेल.भारत
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: Pelé@example.com\r\n"
			), true)).to.be.equal("Pelé@example.com");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: δοκιμή@παράδειγμα.δοκιμή\r\n"
			), true)).to.be.equal("δοκιμή@παράδειγμα.δοκιμή");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: 我買@屋企.香港\r\n"
			), true)).to.be.equal("我買@屋企.香港");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: 二ノ宮@黒川.日本\r\n"
			), true)).to.be.equal("二ノ宮@黒川.日本");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: медведь@с-балалайкой.рф\r\n"
			), true)).to.be.equal("медведь@с-балалайкой.рф");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: संपर्क@डाटामेल.भारत\r\n"
			), true)).to.be.equal("संपर्क@डाटामेल.भारत");

			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: Pelé <Pelé@example.com>\r\n"
			), true)).to.be.equal("Pelé@example.com");
			expect(MsgParser.parseFromHeader(toBinaryString(
				'From: "Pelé" <Pelé@example.com>\r\n'
			), true)).to.be.equal("Pelé@example.com");
			expect(MsgParser.parseFromHeader(toBinaryString(
				'From: "Pelé" <"Pelé"@example.com>\r\n'
			), true)).to.be.equal('"Pelé"@example.com');

			// https://mathiasbynens.be/notes/javascript-unicode#poo-test
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: Iñtërnâtiônàlizætiøn☃💩@Iñtërnâtiônàlizætiøn☃💩.test\r\n"
			), true)).to.be.equal("Iñtërnâtiônàlizætiøn☃💩@Iñtërnâtiônàlizætiøn☃💩.test");
		});
		it("valid IDNA labels", function () {
			// Examples from https://unicode.org/reports/tr46/#Table_Example_Processing
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: <foo@Bloß.de>\r\n"
			), true)).to.be.equal("foo@Bloß.de");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: <foo@xn--blo-7ka.de>\r\n"
			), true)).to.be.equal("foo@xn--blo-7ka.de");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: <foo@u¨.com>\r\n"
			), true)).to.be.equal("foo@u¨.com");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: <foo@xn--tda.com>\r\n"
			), true)).to.be.equal("foo@xn--tda.com");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: <foo@日本語。ＪＰ>\r\n"
			), true)).to.be.equal("foo@日本語。ＪＰ");
			expect(MsgParser.parseFromHeader(toBinaryString(
				"From: <foo@☕.us>\r\n"
			), true)).to.be.equal("foo@☕.us");
		});
		// eslint-disable-next-line mocha/no-skipped-tests
		xit("invalid IDNA labels", function () {
			// Test disabled because currently no check for valid IDNA A-label or U-label is done.

			// Examples from https://unicode.org/reports/tr46/#Table_Example_Processing
			expect(() =>
				MsgParser.parseFromHeader(toBinaryString("From: <foo@xn--u-ccb.com>\r\n"), true)
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader(toBinaryString("From: <foo@a⒈com>\r\n"), true)
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader(toBinaryString("From: <foo@xn--a-ecp.ru>\r\n"), true)
			).to.throw();
			expect(() =>
				MsgParser.parseFromHeader(toBinaryString("From: <foo@xn--0.pt>\r\n"), true)
			).to.throw();
		});
	});
});
