declare module browser {
    declare module jsdns {
        interface TxtResult {
            data: string[]?,
            rcode: number,
            secure: false,
            bogus: false
        }
        const txt: (name: string) => Promise<TxtResult>;
    }
}
