declare module browser {
    declare module migration {
        const getUserPrefs: () => Promise<{[x: string]: boolean|number|string}>;
        const getAccountPrefs: () => Promise<{[x: string]: {[x: string]: boolean|number|string}}>;

        type StoredDkimKeys = import("../modules/dkim/keyStore.mjs.js").StoredDkimKeys;
        const getDkimKeys: () => Promise<StoredDkimKeys?>;

        type DkimStoredUserSignRules = import("../modules/dkim/signRules.mjs.js").DkimStoredUserSignRules;
        const getSignRulesUser: () => Promise<DkimStoredUserSignRules?>;
    }
}
