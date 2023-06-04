////////////////////////////////////////////////////////////////////////////////
//// Mozilla specific modules

interface ChromeUtils {
    import(url: string): any;
    readonly generateQI: (interfaces: nsISupports[]) => nsISupports["QueryInterface"];
}
declare let ChromeUtils: ChromeUtils;

declare module Components {
    let classes: { readonly [key: string]: nsIJSCID };
    let interfaces: ComponentsInterfaces;
    let results: ComponentsResults;
    let utils: ComponentsUtils;

    interface ComponentsInterfaces {
        [key: string]: object;
        readonly amIAddonManagerStartup: amIAddonManagerStartup;
        readonly nsIAsyncInputStream: nsIAsyncInputStream;
        readonly nsIBinaryInputStream: nsIBinaryInputStream;
        readonly nsIFile: nsIFile;
        readonly nsIFileInputStream: nsIFileInputStream;
        readonly nsIInputStreamCallback: nsIInputStreamCallback;
        readonly nsIInputStreamPump: nsIInputStreamPump;
        readonly nsILineInputStream: nsILineInputStream;
        readonly nsIProtocolProxyService: nsIProtocolProxyService;
        readonly nsISocketTransportService: nsISocketTransportService;
        readonly nsIWindowsRegKey: nsIWindowsRegKey;
    }

    interface ComponentsResults {
        [key: string]: number;
    }

    interface ComponentsUtils {
        getGlobalForObject(obj: object): Window;
        unload(url: string): void;
    }
}
declare const Cc: typeof Components.classes;
declare const Ci: typeof Components.interfaces;
declare const Cr: typeof Components.results;
declare const Cu: typeof Components.utils;

/**
 * The `console` global in Chrome context allows creating ConsoleInstance
 * https://searchfox.org/mozilla-central/source/dom/console/ConsoleInstance.h
 */
interface ChromeConsole extends Console {
    readonly createInstance: (aConsoleOptions: {
        prefix?: string,
        maxLogLevel?: "All" | "Debug" | "Log" | "Info" | "Clear" | "Trace" | "TimeLog" | "TimeEnd" | "Time" | "Group" | "GroupEnd" | "Profile" | "ProfileEnd" | "Dir" | "Dirxml" | "Warn" | "Error" | "Off",
        maxLogLevelPref?: string,
        dump?: Function,
        innerID?: sting,
        consoleID?: string,
    }) => Console;
}

declare module ExtensionCommon {
    interface Extension {
        callOnClose(obj: object): void;
        readonly localeData: {
            localizeMessage: (
                messageName: string,
                substitutions?: undefined | string | (string | string[])[]
            ) => string;
        };

        ////////////////////////////////////////////////////////////////////////
        //// https://searchfox.org/comm-central/source/mail/components/extensions/parent/ext-mail.js
        readonly messageManager: {
            readonly convert: (msgDBHdr: nsIMsgDBHdr) => browser.messages.MessageHeader;
            readonly get: (messageId: number) => nsIMsgDBHdr;
        };
        readonly tabManager: ExtensionParentM.TabManagerBase;
        readonly windowManager: ExtensionParentM.WindowManagerBase;
        ////////////////////////////////////////////////////////////////////////

        readonly id: string;
        readonly rootURI: nsIURI;
    }

    declare class ExtensionAPI implements ExtensionApiI {
        constructor(extension: Extension);

        readonly extension: Extension;
    }

    interface Context {
        readonly extension: Extension;
    }
}

declare module ExtensionParentM {
    ////////////////////////////////////////////////////////////////////////////
    //// https://searchfox.org/comm-central/source/mozilla/toolkit/components/extensions/parent/ext-tabs-base.js

    interface NativeTabObj {
        readonly chromeBrowser?: HTMLIFrameElement;
    }
    type NativeTab = NativeTabObj | Window;

    interface TabBase {
        readonly id: number;
        readonly nativeTab: NativeTab;
        // The following is specific to a tab in TB
        // https://searchfox.org/comm-central/source/mail/components/extensions/parent/ext-mail.js
        readonly type: null
        | "messageCompose"
        | "messageDisplay"
        | "content"
        // This list is incomplete, more are specified for TabmailTab
        ;
    }

    interface WindowBase {
        readonly getTabs: () => Generator<TabBase>;
    }

    interface TabTrackerBase {
        readonly getTab: (id: number) => NativeTab;
    }

    interface TabManagerBase {
        readonly get: (tabId: number) => TabBase;
    }

    interface WindowManagerBase {
        readonly getWrapper: (window: Window) => WindowBase | undefined;
    }

    ////////////////////////////////////////////////////////////////////////////

    declare module apiManager {
        declare module global {
            const tabTracker: TabTrackerBase;

            // Returns nsIMsgDBHdr in TB >= 115
            const getDisplayedMessages: (tab: TabBase) => browser.messages.MessageHeader[] | nsIMsgDBHdr[];
        }
    }
}

/**
 * @link https://searchfox.org/comm-central/source/mail/modules/ExtensionSupport.jsm
 */
declare module ExtensionSupportM {
    const registerWindowListener: (
        id: string,
        listener: {
            chromeURLs: string[],
            onLoadWindow: (window: Window) => void,
            onUnloadWindow: (window: Window) => void,
        }
    ) => void;
    const unregisterWindowListener: (id: string) => void;

    const openWindows: Window[];
}

/** JavaScript code module "resource://gre/modules/FileUtils.jsm" */
declare module FileUtils {
    function File(path: string): nsIFile;
}

/** JavaScript code module "resource://gre/modules/osfile.jsm" (removed in TB >= 115) */
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

/** https://searchfox.org/mozilla-central/source/dom/chrome-webidl/PathUtils.webidl */
declare module PathUtils {
    function join(path1: string, path2: string, ...paths: string[]): string;

    const profileDir: string;
}

/** JavaScript code module "resource://gre/modules/Services.jsm" */
declare module Services {
    const appinfo: nsIXULAppInfo;
    const eTLD: nsIEffectiveTLDService;
    const io: nsIIOService;
    const obs: nsIObserverService;
    const prefs: nsIPrefService;
    const tm: nsIThreadManager;
    const vc: nsIVersionComparator;
}

////////////////////////////////////////////////////////////////////////////////
//// Mozilla specific interfaces/types

interface amIAddonManagerStartup {
    readonly registerChrome: (manifestURI: nsIURI, entries: string[][]) => nsIJSRAIIHelper;
}

declare class MozXULElement extends XULElement { };

interface nsIAsyncInputStream extends nsIInputStream {
    readonly asyncWait: (aCallback: nsIInputStreamCallback, aFlags: number, aRequestedCount: number, aEventTarget: nsIEventTarget | null) => void;
}

interface nsIEffectiveTLDService {
    readonly getBaseDomain: (aURI: nsIURI, aAdditionalParts: number = 0) => string;
    readonly getBaseDomainFromHost: (aHost: string, aAdditionalParts: number = 0) => string;
}

interface nsIBinaryInputStream extends nsIInputStream {
    readonly read8: () => number;
    readonly setInputStream: (aInputStream: nsIInputStream) => void;
}

interface nsIDNSRecord { nsIDNSRecord: never };

interface nsIEventTarget { nsIEventTarget: never }

interface nsIInputStream extends nsISupports {
    available(): number;
    close(): void;
    isNonBlocking(): boolean;
}

interface nsIInputStreamCallback extends nsISupports {
    readonly onInputStreamReady: (aStream: nsIAsyncInputStream) => void;
}

interface nsIInputStreamPump extends nsIRequest {
    readonly asyncRead: (aListener: nsIStreamListener, aListenerContext: nsISupports?) => void;
    readonly init: (aStream: nsIInputStream, aSegmentSize: number, aSegmentCount: number, aCloseWhenDone: boolean, aMainThreadTarget?: nsIEventTarget) => void;
}

interface nsIJSCID {
    createInstance(): nsISupports;
    createInstance<nsIIDRef>(uuid: nsIIDRef): nsIIDRef;
    readonly getService: <nsIIDRef>(uuid: nsIIDRef) => nsIIDRef;
}

interface nsIJSRAIIHelper {
    readonly destruct: () => void;
}

interface nsILineInputStream {
    readonly readLine: (aLine: { value: string }) => boolean;
}

interface nsIObserverService {
    readonly notifyObservers: (aSubject: nsISupports?, aTopic: string, someData?: string?) => void;
}

interface nsIRequest { nsIRequest: never }

interface nsIRequestObserver {
    readonly onStartRequest: (aRequest: nsIRequest, aContext: nsISupports) => void;
    readonly onStopRequest: (aRequest: nsIRequest, aStatusCode: nsresult) => void;
}

interface nsISocketTransport extends nsITransport {
    readonly setTimeout: (aType: 0 | 1, aValue: number) => void;

    readonly TIMEOUT_CONNECT: 0;
    readonly TIMEOUT_READ_WRITE: 1;
}

interface nsISocketTransportService {
    /**
     * In TB 78 the nsIDNSRecord did not yet exist. Providing null does not cause an error.
     */
    readonly createTransport: (aSocketTypes: string[], aHost: string, aPort: number, aProxyInfo: nsIProxyInfo?, dnsRecord: nsIDNSRecord?) => nsISocketTransport
}

interface nsIStreamListener extends nsIRequestObserver {
    readonly onDataAvailable: (aRequest: nsIRequest, aContext: nsISupports, aInputStream: nsIInputStream, aOffset: number, aCount: number) => void;
}

interface nsISupports {
    readonly QueryInterface: <nsIIDRef>(uuid: nsIIDRef) => nsIIDRef;
}

interface nsITransport {
    readonly openInputStream: (aFlags: number, aSegmentSize: number, aSegmentCount: number) => nsIInputStream;
    readonly openOutputStream: (aFlags: number, aSegmentSize: number, aSegmentCount: number) => nsIOutputStream;
}

interface nsIThreadManager extends nsISupports {
    readonly mainThreadEventTarget: nsIEventTarget;
}

interface nsIFile {
    readonly exists: () => boolean;
    readonly initWithPath: (filePath: string) => void;
}

interface nsIFileInputStream extends nsIInputStream {
    readonly init: (file: nsIFile, ioFlags: number, perm: number, behaviorFlags: number) => void;
}

interface nsIFileOutputStream extends nsIOutputStream { nsIFileOutputStream: never }

interface nsIOutputStream {
    readonly close: () => void;
    readonly write: (aBuf: string, aCount: number) => number;
}

interface nsIPrefService {
    getBranch(aPrefRoot: string): nsIPrefBranch;
}

interface nsIPrefBranch {
    addObserver(aDomain: string, aObserver: nsIObserver, aHoldWeak: boolean);
    clearUserPref(aPrefName: string);
    getBoolPref(aPrefName: string, aDefaultValue?: boolean): boolean;
    getCharPref(aPrefName: string, aDefaultValue?: string): string;
    getChildList(aStartingAt: string, aCount?: { value?: number }): string[];
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

interface nsIProtocolProxyService {
    readonly newProxyInfo: (
        aType: string,
        aHost: string,
        aPort: number,
        aProxyAuthorizationHeader: string,
        aConnectionIsolationKey: string,
        aFlags: number,
        aFailoverTimeout: number,
        aFailoverProxy: nsIProxyInfo?) => nsIProxyInfo;
}

interface nsIProxyInfo { nsIProxyInfo: never };

type nsIObserver = object;

interface nsIIOService {
    newURI(aSpec: string, aOriginCharset?: string | null, aBaseURI?: nsIURI | null): nsIURI;
}

interface nsIURI {
    readonly resolve: (relativePath: string) => string;
    readonly asciiHost: string;
}

interface nsIVersionComparator {
    readonly compare: (A: string, B: string) => number;
}

interface nsIWindowsRegKey {
    readonly close: () => void;
    readonly hasChild: (name: String) => Boolean;
    readonly hasValue: (name: String) => Boolean;
    readonly open: (rootKey: Number, relPath: String, mode: Number) => void;
    readonly openChild: (relPath: String, mode: Number) => nsIWindowsRegKey;
    readonly readIntValue: (name: String) => Number;
    readonly readStringValue: (name: String) => String;

    readonly ACCESS_QUERY_VALUE: Number;
    readonly ACCESS_READ: Number;
    readonly ROOT_KEY_LOCAL_MACHINE: Number;
}

interface nsIXULAppInfo {
    readonly platformVersion: string;
}

type nsresult = number;

declare class XULElement extends HTMLElement { };

////////////////////////////////////////////////////////////////////////////////
//// Thunderbird specific interfaces

/**
 * expandedfromBox in TB <102
 */
declare class MozMailMultiEmailheaderfield extends MozXULElement {
    /**
     * The description inside `longEmailAddresses` with class "headerValue".
     * Contains a <mail-email address> element.
     */
    emailAddresses: MozXULElement;
    /**
     * The outer hbox with class "headerValueBox"
     */
    longEmailAddresses: MozXULElement;
};
/**
 * expandedfromBox in TB >=102
 */
declare class MultiRecipientRow extends HTMLDivElement {
    recipientsList: HTMLElement;
}
/**
 * fromRecipientX in TB >=102
 */
declare class HeaderRecipient extends HTMLLIElement {
    multiLine: HTMLElement;
}
type expandedfromBox = MozMailMultiEmailheaderfield | MultiRecipientRow;

interface nsIMsgDBHdr {
    getStringProperty(propertyName: string): string;
    setStringProperty(propertyName: string, propertyValue: string): void;
    readonly folder: nsIMsgFolder;
    readonly mime2DecodedAuthor: string;
}

interface nsIMsgFolder {
    getFlag(flag: number): boolean;
    getUriForMsg(msgHdr: nsIMsgDBHdr): string;
    readonly server: nsIMsgIncomingServer;
}

interface nsIMsgIncomingServer {
    getCharValue(attr: string): string;
    getIntValue(attr: string): number;
}
