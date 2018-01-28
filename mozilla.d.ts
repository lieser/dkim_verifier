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
    let stack: nsIStackFrame;
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
    function File(path: string): nsIFile;

    function openSafeFileOutputStream(file: nsIFile, modeFlags?: number): nsIFileOutputStream;
}

/** JavaScript code module "resource://gre/modules/Log.jsm" */
declare module Log {
    function exceptionStr(e: Error): string;

    abstract class Appender {
        constructor(formatter: Formatter);
        append(message: LogMessage): void;
        abstract doAppend(formatted: string): void;

        readonly _formatter: Formatter;
        readonly _name: string;
        level: number;
    }
    class ConsoleAppender extends Appender {
        doAppend(formatted: string): void;
    };
    class DumpAppender extends Appender {};

    abstract class Formatter {
        abstract format(LogMessage): string;
    }
    class BasicFormatter extends Formatter {
        formatText(message: LogMessage): string
    }

    let repository: LoggerRepository;
    let Level: {
        Fatal: 70,
        Error: 60,
        Warn: 50,
        Info: 40,
        Config:	30,
        Debug: 20,
        Trace: 10,
        All: -1,
        Desc: {
            70: "FATAL",
            60: "ERROR",
            50: "WARN",
            40: "INFO",
            30: "CONFIG",
            20: "DEBUG",
            10: "TRACE",
            "-1":  "ALL",
        },
        Numbers: {
            "FATAL": 70,
            "ERROR": 60,
            "WARN": 50,
            "INFO": 40,
            "CONFIG": 30,
            "DEBUG": 20,
            "TRACE": 10,
            "ALL": -1,
        }
    }

    interface LoggerRepository {
        getLogger(name: string): Logger;
    }

    interface Logger {
        addAppender(appender: Appender);

        fatal(text: string, params?: Object): void;
        fatal(error: Error): void;
        error(text: string, params?: Object): void;
        error(error: Error): void;
        warn(text: string, params?: Object): void;
        warn(error: Error): void;
        info(text: string, params?: Object): void;
        config(text: string, params?: Object): void;
        debug(text: string, params?: Object): void;
        debug(error: Error): void;
        trace(text: string, params?: Object): void;

        level: number;
    }

    interface LogMessage {
        loggerName: string;
        level: number;
        levelDesc: string;
        time: number;
        message: string|null;
        params?: Object;
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

/** JavaScript code module "resource://gre/modules/osfile.jsm" */
declare module OS {
    declare module Path {
        function join(path1: string, path2: string, ...paths: string[]): string;
    }

    const Constants: {
        Path: {
            profileDir: string;
        }
    }
}

/** JavaScript code module "resource://gre/modules/Services.jsm" */
declare module Services {
    const appinfo: nsIXULAppInfo;
    const io: nsIIOService;
    const prefs: nsIPrefService;
    const scriptloader: mozIJSSubScriptLoader;
    const storage: mozIStorageService;
    const strings: nsIStringBundleService;
    const vc: nsIVersionComparator;

    interface mozIJSSubScriptLoader {
        loadSubScript(url: string, targetObj?: object , charset?: string): any;
    }
}

/** JavaScript code module "resource://gre/modules/XPCOMUtils.jsm" */
declare module XPCOMUtils {
    function defineLazyModuleGetter(aObject: Object, aName: string, aResource: string, aSymbol?: string): void;
}

////////////////////////////////////////////////////////////////////////////////
//// Thunderbird specific modules

declare module MailServices {
    let accounts: nsIMsgAccountManager
}


////////////////////////////////////////////////////////////////////////////////
//// Mozilla specific interfaces/types

interface mozIStorageConnection {mozIStorageConnection: never}
interface mozIStorageService {
    readonly openDatabase: (aDatabaseFile: nsIFile) => mozIStorageConnection;
}

interface nsIAsyncStreamCopier {nsIAsyncStreamCopier: never}
interface nsIChannel {nsIChannel: never}

interface nsIInputStream {
    available(): number;
    close(): void;
    isNonBlocking(): boolean;
}

interface nsIFile {
    readonly initWithPath: (filePath: string) => void;
}

interface nsIFileInputStream extends nsIInputStream {
    readonly init: (file: nsIFile, ioFlags: number, perm: number, behaviorFlags: number) => void;
}

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

interface nsIStackFrame {
    readonly caller: nsIStackFrame;
    readonly filename: string;
    readonly language: number;
    readonly languageName: string;
    readonly lineNumber: number;
    readonly name: string;
    readonly sourceLine: string;
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

interface nsIVersionComparator {
	readonly compare: (A: string, B: string) => number;
}

interface nsIXULAppInfo {
	readonly platformVersion: string;
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
