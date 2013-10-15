// Default preference values. These are accessible via the preferences system
// or via the optional chrome/content/options.xul preferences dialog.

// general preferences
pref("extensions.dkim_verifier.dns.getNameserversFromOS", true);
pref("extensions.dkim_verifier.dns.nameserver", "8.8.8.8");
pref("extensions.dkim_verifier.dns.timeout_connect", 10);

pref("extensions.dkim_verifier.saveResult", false);


// display preferences
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


// advanced preferences
pref("extensions.dkim_verifier.debug", false);
// "Fatal", "Error", "Warn", "Info", "Config", "Debug", "Trace", "All"
pref("extensions.dkim_verifier.logging.console", "Debug");
// "Fatal", "Error", "Warn", "Info", "Config", "Debug", "Trace", "All"
pref("extensions.dkim_verifier.logging.dump", "Debug");
pref("extensions.dkim_verifier.debugLevel", 0);
pref("extensions.dkim_verifier.error.key_testmode.ignore", false);
