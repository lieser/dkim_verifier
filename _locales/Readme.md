# Localization

If you are a translator new to localize WebExtension,
you may want to read <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Internationalization>
and the [locale-specific message reference](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/i18n/Locale-Specific_Message_reference).

The `messages.json` files contains all localized strings used in the extension.
Note that you don't need to translate the `description` part.
That will never show up in the UI. It is only there to help the translating of the messages,
by e.g. making it more obvious in which context the message is shown.

The `description.txt`, `developerComments.txt` and `privacyPolicy.txt` are not directly used in the extension, and are optional.
They are used for the add-on description on <https://addons.thunderbird.net/thunderbird/addon/dkim-verifier/>.
