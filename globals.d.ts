///<reference path="mozilla.d.ts" />
///<reference path="modules/AuthVerifier.d.ts" />

let Sqlite: any;
let ctypes: any;

////////////////////////////////////////////////////////////////////////////////
//// The following types are defined here instead of with JSDOC,
//// because Visual Studio Code does not support all of JSDOC
//// (e.g. @extends for non class types).

namespace Libunbound {
    interface LibunboundWorker extends Worker {
        onmessage: (this: Worker, ev: WorkerResponse) => any;
        postMessage(message: LoadRequest|ResolveRequest|UpdateCtxRequest, transfer?: any[]): void;
    }

    interface Request {
        callId: number,
        method: string,
    }
    interface LoadRequest extends Request {
        method: "load",
        path: string,
    }
    interface ResolveRequest extends Request {
        method: "resolve",
        name: string,
        rrtype: number,
    }
    interface UpdateCtxRequest extends Request {
        method: "update_ctx",
        getNameserversFromOS: boolean,
        nameservers: string[],
        trustAnchors: string[],
        conf?: string,
        debuglevel?: number,
    }
    interface WorkerRequest extends MessageEvent {
        data: Request;
    }

    interface Log {
        type: string; // "log"
        subType: string;
        message: string;
    }
    interface Response {
        type?: string;
        callId: number;
    }
    interface Result extends Response {
        result: ub_result;
    }
    interface Exception extends Response {
        subType: string;
        message: string;
    }
    interface
    interface WorkerResponse extends MessageEvent {
        data: Log|Response;
    }
}
// for libunboundWorker.jsm
declare function postMessage(WorkerResponse: Libunbound.Log|Libunbound.Result|Libunbound.Exception): void;

////////////////////////////////////////////////////////////////////////////////
//// The following is for Visual Studio Code IntelliSense only:
//// The type detection via JSDoc fails at some places,
//// so we additionally have to specify them here.

interface IDeferred<T> {
    promise: Promise<T>;
    resolve(reason: T): void;
    reject(reason: Error): void;
}
