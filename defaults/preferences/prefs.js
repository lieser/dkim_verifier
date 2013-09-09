// Default preference values. These are accessible via the preferences system
// or via the optional chrome/content/options.xul preferences dialog.

// general preferences
pref("extensions.dkim_verifier.debug", false);
pref("extensions.dkim_verifier.dns.nameserver", "8.8.8.8");
pref("extensions.dkim_verifier.dns.timeout_connect", 10);

pref("extensions.dkim_verifier.error.key_testmode.ignore", false);

// display preferences
pref("extensions.dkim_verifier.alwaysShowDKIMHeader", false);

pref("extensions.dkim_verifier.colorFrom", false);
pref("extensions.dkim_verifier.color.success.text", "windowtext");
pref("extensions.dkim_verifier.color.success.background", "#00FF00");
pref("extensions.dkim_verifier.color.warning.text", "windowtext");
pref("extensions.dkim_verifier.color.warning.background", "orange");
pref("extensions.dkim_verifier.color.permfail.text", "windowtext");
pref("extensions.dkim_verifier.color.permfail.background", "red");
pref("extensions.dkim_verifier.color.nosig.text", "windowtext");
pref("extensions.dkim_verifier.color.nosig.background", "transparent");