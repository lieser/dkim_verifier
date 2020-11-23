declare module browser {
    declare module mailUtils {
        const getBaseDomainFromAddr: (addr: string) => Promise<string>;
    }
}
