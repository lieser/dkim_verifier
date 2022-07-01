interface DKIMHeaderFieldElement extends HTMLDivElement {
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
    _hboxWrapper?: HTMLDivElement
}

declare module browser {
    declare module dkimHeader {
        const showDkimHeader: (tabId: number, messageId: number, show: boolean) => Promise<boolean>;
        const showFromTooltip: (tabId: number, messageId: number, show: boolean) => Promise<boolean>;
        const setDkimHeaderResult: (
            tabId: number,
            messageId: number,
            result: string,
            warnings: string[],
            faviconUrl: string,
            arh: { dkim?: string?, spf?: string?, dmarc?: string?},
        ) => Promise<boolean>;
        const highlightFromAddress: (
            tabId: number,
            messageId: number,
            color: string,
            backgroundColor: string,
        ) => Promise<boolean>;
        const reset: (tabId: number, messageId: number) => Promise<boolean>;
    }
}
