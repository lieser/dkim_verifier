declare module browser {
    declare module jsdns {
        const configure: (
            getNameserversFromOS: boolean,
            nameServer: string,
            timeoutConnect: number,
            proxy: { enable: boolean, type: string, host: string, port: number },
            autoResetServerAlive: boolean,
            debug: boolean,
        ) => Promise<void>;

        type TxtResult = import("../modules/dns.mjs.js").DnsTxtResult | {
            error: string,
        }
        const txt: (name: string) => Promise<TxtResult>;
    }
}
