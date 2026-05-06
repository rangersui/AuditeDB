import { Elastik as BaseElastik } from "@elastikjs/client";
export {
    ElastikError,
    Forbidden,
    InsufficientStorage,
    NetworkError,
    NotFound,
    NotModified,
    PayloadTooLarge,
    PreconditionFailed,
    ServerError,
    Unauthorized,
} from "@elastikjs/client";

export interface StartOptions {
    /** ELASTIK_KEY. Defaults to .env/env or a random hex key. */
    key?: string;
    /** .env/env ELASTIK_HOST or 127.0.0.1. */
    host?: string;
    /** .env/env ELASTIK_PORT or an OS-assigned free port. */
    port?: number;
    /** .env/env ELASTIK_DATA or a fresh temp directory. */
    dataDir?: string;
    /** .env/env ELASTIK_READ_TOKEN or writeToken. Pass "" for public reads. */
    readToken?: string;
    /** .env/env ELASTIK_WRITE_TOKEN or a random session token. Pass "" to disable writes. */
    writeToken?: string;
    /** .env/env ELASTIK_APPROVE_TOKEN or writeToken. */
    approveToken?: string;
    /** Suppress core stdout/stderr while still capturing it for startup errors. Default: true. */
    quiet?: boolean;
    /** Wipe dataDir on stop(). Default: true when dataDir was auto-created. */
    cleanup?: boolean;
}

export interface StartedElastik extends BaseElastik {
    url: string;
    dataDir: string;
    binary: string;
    process: unknown;
    stop(): Promise<void>;
}

export class NoBinaryError extends Error {
    constructor(platform: string, arch: string);
    platform: string;
    arch: string;
}

export function resolveBinary(): string | null;
export function start(options?: StartOptions): Promise<StartedElastik>;

export class Elastik extends BaseElastik {
    static start(options?: StartOptions): Promise<StartedElastik>;
}
