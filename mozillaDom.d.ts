declare let createHeaderEntry: any;
declare let currentHeaderData: any;
declare let gExpandedHeaderView: any;
declare let gFolderDisplay: any;
declare let gMessageDisplay: any;
declare let gMessageListeners: any;
declare let syncGridColumnWidths: any;

interface Document {
    createXULElement(tagName: string, options?: ElementCreationOptions): XULElement;
}

interface Window {
    readonly gMessageListeners: object[];
}
