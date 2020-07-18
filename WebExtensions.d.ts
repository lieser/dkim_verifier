/// <reference types="firefox-webext-browser" />

declare module browser {
    interface Event<EventListener> {
        readonly addListener(listener: EventListener),
        readonly removeListener(listener: EventListener),
        readonly hasListener(listener: EventListener),
    }

    declare module accounts {
        interface MailAccount {
            id: string,
            name: string,
            type: string,
        }

        const list: () => Promise<MailAccount[]>;
        const get: (accountId) => Promise<MailAccount?>;
    }

    declare module folder {
        interface MailFolder {
            accountId: string,
        }
    }

    declare module messages {
        interface MessagePart {
            body?: string,
            contentType?: string,
            headers?: { [x: string]: string[] },
            name?: string,
            partNam?: string,
            parts?: MessagePart[],
            size?: number,
        }

        const getFull: (messageId: number) => MessagePart;
        const getRaw: (messageId: number) => string;
    }

    declare module messageDisplay {
        interface MessageHeader {
            author: string,
            bccList: string[],
            ccList: string[],
            date: Date,
            flagged: boolean,
            folder: folder.MailFolder,
            id: number,
            junk: boolean,
            junkScore: number,
            read: boolean,
            recipients: string[],
            subject: string,
            tags: string[],
        }

        const onMessageDisplayed: Event<(tabId: { id: number, windowID: number }, message: MessageHeader) => void>,
    }
}
