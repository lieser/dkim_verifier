declare module browser {
    interface Event<EventListener> {
        readonly addListener(listener: EventListener),
        readonly removeListener(listener: EventListener),
        readonly hasListener(listener: EventListener),
    }

    declare module i18n {
        const getMessage: (
            messageName: string,
            substitutions?: undefined | string | (string | string[])[]
        ) => string;
    }

    declare module messages {
        const getRaw: (messageId: number) => string;
    }

    declare module messageDisplay {
        interface MessageHeader {
            author: string,
            bccList: string[],
            ccList: string[],
            date: Date,
            flagged: boolean,
            folder: MailFolder,
            id: number,
            junk: boolean,
            junkScore: number,
            read: boolean,
            recipients: string[],
            subject: string,
            tags: string[],
        }

        const onMessageDisplayed: Event<(tabId: number, message: MessageHeader) => void>,
    }

    declare module windows {
        interface getInfo {
            populate?: boolean,
            windowTypes?: WindowType,
        }
        interface Tab { WindowType: Tab }
        interface WindowState { WindowState: never }
        interface WindowType { WindowType: never }
        interface Window {
            alwaysOnTop: boolean,
            focused: boolean,
            incognito: boolean,
            height?: number,
            id?: number,
            left?: number
            state?: WindowState,
            tabs?: Tab[],
            title?: string,
            top?: number,
            type?: WindowType,
            width?: number,
        }

        const getCurrent: (getInfo?: getInfo) => Promise<Window>;
    }
}
