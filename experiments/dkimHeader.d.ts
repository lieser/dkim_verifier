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
        const setDkimHeaderResult: (tabId: number, result: string, warnings: string[], faviconUrl: string) => void;
    }
}
