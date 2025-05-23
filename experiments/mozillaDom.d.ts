interface Document {
    createXULElement(tagName: string, options?: ElementCreationOptions): XULElement;
}

interface Window {
    readonly gMessageListeners: object[];
    readonly updateExpandedView: () => void;
}
