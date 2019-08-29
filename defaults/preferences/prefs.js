// Default preference values. These are accessible via the preferences system
// or via the optional chrome/content/options.xul preferences dialog.
/* eslint strict: "off", no-magic-numbers: "off" */
/* global pref */
// @ts-nocheck

////////////////////////////////////////////////////////////////////////////////
// general preferences - General
////////////////////////////////////////////////////////////////////////////////

pref("extensions.dkim_verifier.dkim.enable", true);

// 0: don't store DKIM keys
// 1: store DKIM keys
// 2: store DKIM keys and compare with current key
pref("extensions.dkim_verifier.key.storing", 0);

pref("extensions.dkim_verifier.saveResult", false);
pref("extensions.dkim_verifier.arh.read", false);

////////////////////////////////////////////////////////////////////////////////
// general preferences - DNS
////////////////////////////////////////////////////////////////////////////////

/*
 * 1 JS DNS
 * 2 libunbound
 */
pref("extensions.dkim_verifier.dns.resolver", 1);
pref("extensions.dkim_verifier.dns.getNameserversFromOS", true);
pref("extensions.dkim_verifier.dns.nameserver", "8.8.8.8");
pref("extensions.dkim_verifier.dns.timeout_connect", 5);
pref("extensions.dkim_verifier.dns.dnssec.trustAnchor", ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D");
pref("extensions.dkim_verifier.dns.proxy.enable", false);
// "socks", "socks4"
pref("extensions.dkim_verifier.dns.proxy.type", "socks");
pref("extensions.dkim_verifier.dns.proxy.host", "");
pref("extensions.dkim_verifier.dns.proxy.port", "");
pref("extensions.dkim_verifier.dns.jsdns.autoResetServerAlive", false);
pref("extensions.dkim_verifier.dns.libunbound.path", "extensions/dnssec@nic.cz/plugins/ub_ds_windows-x86.dll");
pref("extensions.dkim_verifier.dns.libunbound.path.relToProfileDir", true);


////////////////////////////////////////////////////////////////////////////////
// general preferences - Policy
////////////////////////////////////////////////////////////////////////////////

pref("extensions.dkim_verifier.policy.signRules.enable", false);
pref("extensions.dkim_verifier.policy.signRules.checkDefaultRules", true);
pref("extensions.dkim_verifier.policy.signRules.autoAddRule", false);
pref("extensions.dkim_verifier.policy.signRules.autoAddRule.onlyIfFromAddressInSDID", true);
// 0: from address
// 1: subdomain
// 2: base domain
pref("extensions.dkim_verifier.policy.signRules.autoAddRule.for", 0);
pref("extensions.dkim_verifier.policy.signRules.sdid.allowSubDomains", true);
pref("extensions.dkim_verifier.error.policy.wrong_sdid.asWarning", false);

pref("extensions.dkim_verifier.policy.DMARC.shouldBeSigned.enable", false);
// "none", "quarantine", "reject"
pref("extensions.dkim_verifier.policy.DMARC.shouldBeSigned.neededPolicy", "none");


////////////////////////////////////////////////////////////////////////////////
// display preferences
////////////////////////////////////////////////////////////////////////////////

/*
 * 0   never
 * 10  when an e-mail with a valid DKIM signature is viewed  (SUCCESS)
 * 20  when an e-mail with a valid DKIM signature is viewed (including TEMPFAIL) (SUCCESS, TEMPFAIL)
 * 30  when an e-mail with a DKIM signature is viewed (SUCCESS, TEMPFAIL, PERMFAIL, loading)
 * 40  when an e-mail is viewed
 * 50  when a message is viewed
 */
pref("extensions.dkim_verifier.showDKIMHeader", 30);
/*
 * 0   never
 * 10  when an e-mail with a valid DKIM signature is viewed  (SUCCESS)
 * 20  when an e-mail with a valid DKIM signature is viewed (including TEMPFAIL) (SUCCESS, TEMPFAIL)
 * 30  when an e-mail with a DKIM signature is viewed (SUCCESS, TEMPFAIL, PERMFAIL, loading)
 * 40  when an e-mail is viewed
 * 50  when a message is viewed
 */
pref("extensions.dkim_verifier.showDKIMStatusbarpanel", 0);
/*
 * 1 text
 * 2 icon
 */
pref("extensions.dkim_verifier.statusbarpanel.result.style", 1);
/*
 * 0   never
 * 10  when an e-mail with a valid DKIM signature is viewed  (SUCCESS)
 * 20  when an e-mail with a valid DKIM signature is viewed (including TEMPFAIL) (SUCCESS, TEMPFAIL)
 * 30  when an e-mail with a DKIM signature is viewed (SUCCESS, TEMPFAIL, PERMFAIL, loading)
 * 40  when an e-mail is viewed
 * 50  when a message is viewed
 */
pref("extensions.dkim_verifier.showDKIMFromTooltip", 0);

pref("extensions.dkim_verifier.colorFrom", false);
pref("extensions.dkim_verifier.color.success.text", "windowtext");
pref("extensions.dkim_verifier.color.success.background", "#00FF00");
pref("extensions.dkim_verifier.color.warning.text", "windowtext");
pref("extensions.dkim_verifier.color.warning.background", "orange");
pref("extensions.dkim_verifier.color.permfail.text", "windowtext");
pref("extensions.dkim_verifier.color.permfail.background", "red");
pref("extensions.dkim_verifier.color.tempfail.text", "windowtext");
pref("extensions.dkim_verifier.color.tempfail.background", "transparent");
pref("extensions.dkim_verifier.color.nosig.text", "windowtext");
pref("extensions.dkim_verifier.color.nosig.background", "transparent");

pref("extensions.dkim_verifier.display.favicon.show", true);


////////////////////////////////////////////////////////////////////////////////
// advanced preferences
////////////////////////////////////////////////////////////////////////////////

pref("extensions.dkim_verifier.debug", false);
// "Fatal", "Error", "Warn", "Info", "Config", "Debug", "Trace", "All"
pref("extensions.dkim_verifier.logging.console", "Debug");
// "Fatal", "Error", "Warn", "Info", "Config", "Debug", "Trace", "All"
pref("extensions.dkim_verifier.logging.dump", "Debug");
pref("extensions.dkim_verifier.debugLevel", 0);
pref("extensions.dkim_verifier.error.detailedReasons", false);
pref("extensions.dkim_verifier.display.keySecure", true);
pref("extensions.dkim_verifier.arh.replaceAddonResult", true);
pref("extensions.dkim_verifier.arh.relaxedParsing", false);
// 0: error, 1: warning, 2: ignore
pref("extensions.dkim_verifier.error.illformed_i.treatAs", 1);
pref("extensions.dkim_verifier.error.illformed_s.treatAs", 1);
pref("extensions.dkim_verifier.error.policy.key_insecure.treatAs", 2);
pref("extensions.dkim_verifier.error.key_testmode.ignore", false);
pref("extensions.dkim_verifier.error.contentTypeCharsetAddedQuotes.treatAs", 0);
pref("extensions.dkim_verifier.error.algorithm.sign.rsa-sha1.treatAs", 1);
pref("extensions.dkim_verifier.error.algorithm.rsa.weakKeyLength.treatAs", 1);


////////////////////////////////////////////////////////////////////////////////
// account specific options
////////////////////////////////////////////////////////////////////////////////

// 0: default, 1: yes, 2: no
pref("mail.server.default.dkim_verifier.dkim.enable", 0);
pref("mail.server.default.dkim_verifier.arh.read", 0);
// empty to allow all
pref("mail.server.default.dkim_verifier.arh.allowedAuthserv", "");
