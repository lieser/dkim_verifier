declare module browser {
    declare module jsdns {
        const txt: (name: string) => Promise<{
            data: string,
            rcode: number,
            secure: false,
            bogus: false
        }>;
    }
}
