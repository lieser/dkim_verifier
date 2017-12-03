declare module Components {
    let classes: Array;
    let interfaces: Components_interfaces;
    let results: Components_results;
    let utils: Components_utils;
}

declare module Services {
    let prefs: nsIPrefService;
    let scriptloader: mozIJSSubScriptLoader;
    let strings: nsIStringBundleService;
}

declare module MailServices {
    let accounts: nsIMsgAccountManager
}

interface Components_interfaces {
    [key: string]: object;
    readonly nsMsgFolderFlags: nsMsgFolderFlags;
    readonly nsIMsgIdentity: nsIMsgIdentity;
}

interface Components_results {
    [key: string]: number;
}

interface Components_utils {
    import(url: string, scope?: object): object;
}

interface mozIJSSubScriptLoader {
    loadSubScript(url: string, targetObj?: object , charset?: string): any;
}

interface nsIPrefService {
    getBranch(aPrefRoot: string): nsIPrefBranch;
}

interface nsIPrefBranch {
    addObserver(aDomain: string, aObserver: nsIObserver, aHoldWeak: boolean);
    clearUserPref(aPrefName: string);
    getBoolPref(aPrefName: string, aDefaultValue?: boolean): boolean;
    getCharPref(aPrefName: string, aDefaultValue?: string): string;
    getIntPref(aPrefName: string, aDefaultValue?: number): number;
    prefHasUserValue(aPrefName: string): boolean;
    setIntPref(aPrefName: string, aValue: number);
    removeObserver(aDomain: string, aObserver: nsIObserver);
}

type nsIObserver = object;

interface nsIStringBundleService {
    createBundle(aURLSpec: string): nsIStringBundle;
}

interface nsIStringBundle {
    formatStringFromName(aName: string, params: string[], length: number): string;
    GetStringFromName(aName: string): string;
}

interface nsIMsgDBHdr {
    getStringProperty(propertyName: string): string;
    setStringProperty(propertyName: string, propertyValue: string);
    readonly folder: nsIMsgFolder;
    readonly mime2DecodedAuthor: string;
}

interface nsIMsgFolder {
    getFlag(flag: number): boolean;
    getUriForMsg(msgHdr: nsIMsgDBHdr): string;
    readonly server: nsIMsgIncomingServer;
}

interface nsMsgFolderFlags {
    readonly SentMail: number;
}

interface nsIMsgIncomingServer {
    getCharValue(attr: string): string;
    getIntValue(attr: string): number;
}

interface nsIMsgAccountManager {
    getIdentitiesForServer(server: nsIMsgIncomingServer): nsIMsgIdentity[];
}

interface nsIMsgIdentity {
    email: string;
}

declare function fixIterator<T>(obj: any, type: T): T[]
