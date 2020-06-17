interface DKIMHeaderFieldElement extends XULElement {
    _dkimValue: XULElement
    _dkimWarningIcon: XULElement
    _dkimWarningTooltip: DKIMTooltipElement
    _arhDkim: { box: XULElement, value: XULElement }
    _arhDmarc: { box: XULElement, value: XULElement }
    _arhSpf: { box: XULElement, value: XULElement }
}

interface DKIMTooltipElement extends XULElement {
    _value: XULElement | void
    _warningsBox: XULElement
}

interface DKIMFaviconElement extends XULElement {
    _dkimTooltipFromElement: DKIMTooltipElement
}

declare module browser {
    declare module dkimHeader {
        const showDkimHeader: (tabId: number, show: boolean) => Promise<void>;
        const showFromTooltip: (tabId: number, show: boolean) => Promise<void>;
        const setDkimHeaderResult: (
            tabId: number,
            result: string,
            warnings: string[],
            faviconUrl: string,
            arh: { dkim?: string?, spf?: string?, dmarc?: string?},
        ) => Promise<void>;
        const highlightFromAddress: (tabId: number, color: string, backgroundColor: string) => Promise<void>;
    }
}
