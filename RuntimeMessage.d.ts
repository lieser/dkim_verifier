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

        interface deleteRule extends SignRulesMessage {
            readonly method: "deleteRule";
            readonly parameters: {
                readonly id: number,
            }
        }

        type Messages = getDefaultRules | getUserRules | exportUserRules | importUserRules | addRule | updateRule | deleteRule;
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

        interface deleteKey extends KeyDbMessage {
            readonly method: "deleteKey";
            readonly parameters: {
                readonly id: number;
            }
        }

        type Messages = getKeys | updateKey | deleteKey;
    }

    namespace DisplayAction {
        interface DisplayActionMessage extends DkimMessage {
            readonly module: "DisplayAction";
            readonly parameters: {
                readonly tabId: number;
            }
        }

        interface queryButtonState extends DisplayActionMessage {
            readonly method: "queryButtonState";
        }
        interface queryButtonStateResult {
            readonly reverifyDKIMSignature: boolean;
            readonly policyAddUserException: boolean;
            readonly markKeyAsSecure: boolean;
            readonly updateKey: boolean;
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

        type Messages = queryButtonState | reverifyDKIMSignature | policyAddUserException | markKeyAsSecure | updateKey;
    }

    type Messages = SignRules.Messages | KeyDb.Messages | DisplayAction.Messages;
}
