////////////////////////////////////////////////////////////////////////////////
//// Mozilla specific JS extensions

declare function fixIterator<T>(obj: any, type: T): T[]

interface Object extends Object {
    toSource(): string;
}


////////////////////////////////////////////////////////////////////////////////
//// Mozilla specific modules

declare module Components {
    let classes: Array;
    let interfaces: ComponentsInterfaces;
    let results: ComponentsResults;
    let utils: ComponentsUtils;

    function isSuccessCode(returnCode: nsresult): boolean;

    interface ComponentsInterfaces {
        [key: string]: object;
        readonly nsMsgFolderFlags: nsMsgFolderFlags;
        readonly nsIMsgIdentity: nsIMsgIdentity;
    }

    interface ComponentsResults {
        [key: string]: number;
    }

    interface ComponentsUtils {
        import(url: string, scope?: object): object;
    }
}

/** JavaScript code module "resource://gre/modules/FileUtils.jsm" */
declare module FileUtils {
    function openSafeFileOutputStream(file: nsIFile, modeFlags?: number): nsIFileOutputStream;
}

/** JavaScript code module "resource://gre/modules/Log.jsm" */
declare module Log {
    function exceptionStr(e: Error): string;

    class Appender {
        constructor(formatter: Formatter);
        level: number;
    }
    class ConsoleAppender extends Appender {};
    class DumpAppender extends Appender {};

    class Formatter {}

    let repository: LoggerRepository;
    let Level: {
        All: 0,
        Config:	30,
        Debug: 20,
        // Desc 	{ 0: "ALL", 10: "TRACE", 20: "DEBUG", 30: "CONFIG", 40: "INFO", 50: "WARN", 60: "ERROR", 70: "FATAL" }
        Error: 30,
        Fatal: 70,
        Info: 40,
        // Numbers 	{ "ALL": 0, "TRACE": 10, "DEBUG": 20, "CONFIG": 30, "INFO": 40, "WARN": 50, "ERROR": 60, "FATAL": 70 }
        Trace: 10,
        Warn: 50
    }

    interface LoggerRepository {
        getLogger(name: string): Logger;
    }

    interface Logger {
        addAppender(appender: Appender);

        fatal(text: string, params?: Object): void;
        error(text: string, params?: Object): void;
        warn(text: string, params?: Object): void;
        info(text: string, params?: Object): void;
        config(text: string, params?: Object): void;
        debug(text: string, params?: Object): void;
        trace(text: string, params?: Object): void;

        level: number;
    }
}

/** JavaScript code module "resource://gre/modules/NetUtil.jsm" */
declare module NetUtil {
    function asyncCopy(aSource: nsIInputStream, aSink: nsIOutputStream, aCallback?: (status: nsresult) => void): nsIAsyncStreamCopier;
    function asyncFetch(aSource: aWhatToLoad|nsIChannel|nsIInputStream, aCallback: asyncFetchCallback): void
    function newURI(aTarget: string|nsIFile, aOriginCharset?, aBaseURI?: nsIURI): nsIURI;
    function readInputStreamToString(aInputStream: nsIInputStream, aCount: number, aOptions?): string;

    interface asyncFetchCallback { (inputStream: nsIInputStream, status: nsresult, request: nsIRequest): void }

    interface aWhatToLoad {
        uri: string | nsIURI | nsIFile;
        loadingNode?;
        loadingPrincipal?;
        triggeringPrincipal?;
        securityFlags?;
        contentPolicyType?;
        loadUsingSystemPrincipal?: boolean;
    };
}

/** JavaScript code module "resource://gre/modules/Services.jsm" */
declare module Services {
    let io: nsIIOService;
    let prefs: nsIPrefService;
    let scriptloader: mozIJSSubScriptLoader;
    let strings: nsIStringBundleService;

    interface mozIJSSubScriptLoader {
        loadSubScript(url: string, targetObj?: object , charset?: string): any;
    }
}


////////////////////////////////////////////////////////////////////////////////
//// Thunderbird specific modules

declare module MailServices {
    let accounts: nsIMsgAccountManager
}


////////////////////////////////////////////////////////////////////////////////
//// Mozilla specific interfaces/types

interface nsIAsyncStreamCopier {nsIAsyncStreamCopier: never}
interface nsIChannel {nsIChannel: never}

interface nsIInputStream {
    available(): number;
    close(): void;
    isNonBlocking(): boolean;
}

interface nsIFile {nsIFile: never}

interface nsIFileOutputStream extends nsIOutputStream {nsIFileOutputStream: never}

interface nsIOutputStream {nsIOutputStream: never}

interface nsIPrefService {
    getBranch(aPrefRoot: string): nsIPrefBranch;
}

interface nsIPrefBranch {
    addObserver(aDomain: string, aObserver: nsIObserver, aHoldWeak: boolean);
    clearUserPref(aPrefName: string);
    getBoolPref(aPrefName: string, aDefaultValue?: boolean): boolean;
    getCharPref(aPrefName: string, aDefaultValue?: string): string;
    getIntPref(aPrefName: string, aDefaultValue?: number): number;
    getPrefType(aPrefName: string): number;
    prefHasUserValue(aPrefName: string): boolean;
    setIntPref(aPrefName: string, aValue: number);
    removeObserver(aDomain: string, aObserver: nsIObserver);
    readonly PREF_INVALID: number;
    readonly PREF_STRING: number;
    readonly PREF_INT: number;
    readonly PREF_BOOL: number;
}

type nsIObserver = object;

interface nsIIOService {
    newURI(aSpec: string, aOriginCharset: string|null, aBaseURI: nsIURI|null): nsIURI;
}

interface nsIStringBundleService {
    createBundle(aURLSpec: string): nsIStringBundle;
}

interface nsIStringBundle {
    formatStringFromName(aName: string, params: string[], length: number): string;
    GetStringFromName(aName: string): string;
}

interface nsIURI {
    readonly asciiHost: string;
}

interface nsresult {nsresult: never};

////////////////////////////////////////////////////////////////////////////////
//// Thunderbird specific interfaces

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
