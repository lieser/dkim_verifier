declare module browser {
    declare module storageMessage {
        const set: (messageId: number, key: string, value: string) => Promise<void>;
        const get: (messageId: number, key: string) => Promise<string>;
    }
}
