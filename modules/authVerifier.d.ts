// The following is for Visual Studio Code IntelliSense only:
// The type detection via JSDoc fails at some places, so we additionally have to specify them here.
declare module IAuthVerifier {
    type dkimSigResultV2 = import("./dkim/verifier.mjs.js").dkimSigResultV2;

    interface AuthResultDKIMV2 extends dkimSigResultV2 {
        res_num: number;
        // 10: SUCCESS
        // 20: TEMPFAIL
        // 30: PERMFAIL
        // 35: PERMFAIL treat as no sig
        // 40: no sig
        result_str: string; // localized result string
        error_str?: string; // localized error string
        warnings_str?: string[]; // localized warnings
        favicon?: string | undefined; // url to the favicon of the sdid
    }
}
