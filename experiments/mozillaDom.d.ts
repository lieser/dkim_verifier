interface Document {
    createXULElement(tagName: string, options?: ElementCreationOptions): XULElement;
}

interface Window {
    readonly gFolderDisplay: { selectedMessage: nsIMsgDBHdr };
    readonly gMessageListeners: object[];
}
