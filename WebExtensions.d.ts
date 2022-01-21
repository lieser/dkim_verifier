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
            identities: MailIdentity[],
            name: string,
            type: string,
        }

        interface MailIdentity {
            email: string,
        }

        const list: () => Promise<MailAccount[]>;
        const get: (accountId: string) => Promise<MailAccount?>;
    }

    declare module folder {
        interface MailFolder {
            accountId: string,
            type?: string | undefined,
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

        const getDisplayedMessage: (tabId: number) => Promise<MessageHeader>;
        const onMessageDisplayed: Event<(tabId: messenger.tabs.Tab, message: MessageHeader) => void>,
        const onMessagesDisplayed: Event<(tabId: messenger.tabs.Tab, message: MessageHeader[]) => void>,
    }
}

declare module messenger {
    declare module tabs {
        interface Tab {
            id: number,
            windowID: number,
            url?: string,
        }
    }
}
