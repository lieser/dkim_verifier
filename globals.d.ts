///<reference path="mozilla.d.ts" />
///<reference path="modules/AuthVerifier.d.ts" />

let Sqlite: any;

////////////////////////////////////////////////////////////////////////////////
//// The following is for Visual Studio Code IntelliSense only:
//// The type detection via JSDoc fails at some places,
//// so we additionally have to specify them here.

interface IDeferred<T> {
    promise: Promise<T>;
    resolve(reason: T): void;
    reject(reason: Error): void;
}
