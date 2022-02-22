interface Document {
    createXULElement(tagName: string, options?: ElementCreationOptions): XULElement;
}

interface Window {
    readonly gFolderDisplay: { selectedMessage: nsIMsgDBHdr };
    readonly gMessageListeners: object[];
    // Removed in TB 99
    readonly OnResizeExpandedHeaderView?: () => void;
    readonly syncGridColumnWidths: () => void;
}
