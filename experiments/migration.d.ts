declare module browser {
    declare module migration {
        const getUserPrefs: () => Promise<{[x: string]: boolean|number|string}>;
        const getAccountPrefs: () => Promise<{[x: string]: {[x: string]: boolean|number|string}}>;

        type DkimStoredUserSignRules = import("../modules/dkim/signRules.mjs.js").DkimStoredUserSignRules;
        const getSignRulesUser: () => Promise<DkimStoredUserSignRules?>;
    }
}
