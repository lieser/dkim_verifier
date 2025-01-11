declare module browser {
    declare module accounts {
        // https://github.com/thundernest/webext-docs/issues/56
        var get: (accountId: string) => Promise<MailAccount?>;
    }
}
