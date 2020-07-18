declare module browser {
    declare module migration {
        const getUserPrefs: () => Promise<{[x: string]: boolean|number|string}>;
        const getAccountPrefs: () => Promise<{[x: string]: {[x: string]: boolean|number|string}}>;
    }
}
