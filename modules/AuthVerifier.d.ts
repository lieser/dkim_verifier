// The following is for Visual Studio Code IntelliSense only:
// The type detection via JSDoc fails at some places, so we additionally have to specify them here.
type AuthResultV2 = AuthResult
type SavedAuthResultV3 = SavedAuthResult
type AuthResultDKIMV2 = AuthResultDKIM

declare module IAuthVerifier {
    interface IAuthResultV2 extends AuthResultV2 {
        dkim: AuthResultDKIMV2[];
    };
    export type IAuthResult = IAuthResultV2;

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
        favicon?: string; // url to the favicon of the sdid
    }
    export type AuthResultDKIM = AuthResultDKIMV2;
}
