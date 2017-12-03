
let Sqlite: any;

namespace Log {
    declare function exceptionStr(e: Error): string;
}


// The following is for Visual Studio Code IntelliSense only:
// The type detection via JSDoc fails at some places, so we additionally have to specify them here.
namespace _DKIM_Verifier {
    let _AuthVerifier = AuthVerifier;
    let _Key = Key;
    let _Logging = Logging;
    let _Policy = Policy;
    let _Verifier = Verifier;
    // helper.jsm
    let _DKIM_InternalError = DKIM_InternalError;
    let _exceptionToStr = exceptionToStr;
}

namespace DKIM_Verifier {
    let AuthVerifier = _DKIM_Verifier._AuthVerifier;
    let Display = any;
    let Key = _DKIM_Verifier._Key;
    let Logging = _DKIM_Verifier._Logging;
    let Policy = _DKIM_Verifier._Policy;
    // helper.jsm
    let DKIM_InternalError = _DKIM_Verifier._DKIM_InternalError;
    let exceptionToStr = _DKIM_Verifier._exceptionToStr;
    let XexceptionToStr = _DKIM_Verifier._exceptionToStr;
};

namespace DKIM {
    let Policy = _DKIM_Verifier._Policy;
    let Verifier = _DKIM_Verifier._Verifier;
};


interface IDeferred<T> {
    promise: Promise<T>;
    resolve: any;
    reject: any;
}

