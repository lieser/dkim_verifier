interface Document {
    createXULElement(tagName: string, options?: ElementCreationOptions): XULElement;
}

interface Window {
    // Removed in TB 111
    readonly gFolderDisplay?: { selectedMessage: nsIMsgDBHdr };
    readonly gMessageListeners: object[];
    // Removed in TB 99
    readonly OnResizeExpandedHeaderView?: () => void;
    // Removed in TB 102
    readonly syncGridColumnWidths?: () => void;
    readonly updateExpandedView: () => void;
}
