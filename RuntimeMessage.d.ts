namespace RuntimeMessage {
    interface DkimMessage {
        readonly module: string;
        readonly method: string;
    }

    namespace SignRules {
        interface SignRulesMessage extends DkimMessage {
            readonly module: "SignRules";
        }

        interface getDefaultRules extends SignRulesMessage {
            readonly method: "getDefaultRules";
        }

        interface getUserRules extends SignRulesMessage {
            readonly method: "getUserRules";
        }

        interface exportUserRules extends SignRulesMessage {
            readonly method: "exportUserRules";
        }

        interface importUserRules extends SignRulesMessage {
            readonly method: "importUserRules";
            readonly parameters: {
                readonly data: any,
                readonly replace: boolean,
            }
        }

        interface addRule extends SignRulesMessage {
            readonly method: "addRule";
            readonly parameters: {
                readonly domain: string?,
                readonly listId: string?,
                readonly addr: string,
                readonly sdid: string,
                readonly type: type,
                readonly priority: number?,
                readonly enabled: boolean,
            }
        }

        interface updateRule extends SignRulesMessage {
            readonly method: "updateRule";
            readonly parameters: {
                readonly id: number,
                readonly propertyName: string,
                readonly newValue: any,
            }
        }

        interface deleteRules extends SignRulesMessage {
            readonly method: "deleteRules";
            readonly parameters: {
                readonly ids: number[],
            }
        }

        type Messages = getDefaultRules | getUserRules | exportUserRules | importUserRules | addRule | updateRule | deleteRules;
    }

    namespace KeyDb {
        interface KeyDbMessage extends DkimMessage {
            readonly module: "KeyDb";
        }

        interface getKeys extends KeyDbMessage {
            readonly method: "getKeys";
        }

        interface updateKey extends KeyDbMessage {
            readonly method: "updateKey";
            readonly parameters: {
                readonly id: number;
                readonly propertyName: string;
                readonly newValue: any;
            }
        }

        interface deleteKeys extends KeyDbMessage {
            readonly method: "deleteKeys";
            readonly parameters: {
                readonly ids: number[];
            }
        }

        type Messages = getKeys | updateKey | deleteKeys;
    }

    namespace DisplayAction {
        interface DisplayActionMessage extends DkimMessage {
            readonly module: "DisplayAction";
            readonly parameters: {
                readonly tabId: number;
            }
        }

        interface queryResultState extends DisplayActionMessage {
            readonly method: "queryResultState";
        }
        interface queryResultStateResult {
            readonly reverifyDKIMSignature: boolean;
            readonly policyAddUserException: boolean;
            readonly markKeyAsSecure: boolean;
            readonly updateKey: boolean;
            readonly dkim: AuthResultDKIM[];
        }

        interface reverifyDKIMSignature extends DisplayActionMessage {
            readonly method: "reverifyDKIMSignature";
        }

        interface policyAddUserException extends DisplayActionMessage {
            readonly method: "policyAddUserException";
        }

        interface markKeyAsSecure extends DisplayActionMessage {
            readonly method: "markKeyAsSecure";
        }

        interface updateKey extends DisplayActionMessage {
            readonly method: "updateKey";
        }

        type Messages = queryResultState | reverifyDKIMSignature | policyAddUserException | markKeyAsSecure | updateKey;
    }

    type Messages = SignRules.Messages | KeyDb.Messages | DisplayAction.Messages;
}
