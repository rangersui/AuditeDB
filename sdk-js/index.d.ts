/// <reference lib="dom" />
/// <reference lib="dom.iterable" />

export type HeaderMap = Record<string, string>;
export type FetchLike = typeof fetch;
export type RequestBody = string | ArrayBuffer | ArrayBufferView | Blob | ReadableStream<Uint8Array> | null | undefined;

export interface ElastikOptions {
    /** Preferred write token. Falls through to read/approve unless overridden. */
    writeToken?: string;
    /** Backwards-compatible alias for writeToken. */
    token?: string;
    /** Token for GET / HEAD / listen. Defaults to writeToken. */
    readToken?: string;
    /** Token for DELETE and protected writes. Defaults to writeToken. */
    approveToken?: string;
    /** Custom fetch implementation for tests, polyfills, Workers, etc. */
    fetch?: FetchLike;
}

export interface CorsOptions {
    origin?: string;
    methods?: string | string[];
    allowHeaders?: string | string[];
    exposeHeaders?: string | string[];
    credentials?: boolean;
    maxAge?: number | string;
}

export interface BrowserPolicyOptions {
    cors?: boolean | string | CorsOptions;
    csp?: string;
    cspReportOnly?: string;
    frameOptions?: string;
    coop?: string;
    coep?: string;
    corp?: string;
    cache?: string;
    expires?: string | Date;
    disposition?: string;
    language?: string;
    encoding?: string;
    referrerPolicy?: string;
    robots?: string;
}

export interface CommonOptions {
    headers?: HeaderMap;
    signal?: AbortSignal;
}

export interface PutOptions extends CommonOptions, BrowserPolicyOptions {
    contentType?: string;
    /** Preferred alias for If-Match. */
    ifMatch?: string;
    /** Backwards-compatible alias for ifMatch. */
    etag?: string;
    ifNoneMatch?: string;
}

export interface PostOptions extends CommonOptions {
    /** Preferred alias for If-Match. */
    ifMatch?: string;
    /** Backwards-compatible alias for ifMatch. */
    etag?: string;
}

export interface DeleteOptions extends CommonOptions {
    /** Preferred alias for If-Match. */
    ifMatch?: string;
    /** Backwards-compatible alias for ifMatch. */
    etag?: string;
}

export interface GetOptions extends CommonOptions {
    range?: string;
    ifNoneMatch?: string;
    ifMatch?: string;
    meta?: false;
}

export interface GetMetaOptions extends CommonOptions {
    range?: string;
    ifNoneMatch?: string;
    ifMatch?: string;
    meta: true;
}

export interface HeadOptions extends CommonOptions {}

export interface RequestOptions extends CommonOptions {
    body?: RequestBody;
    /** Explicit bearer token for this raw request. Defaults by method/path. */
    token?: string;
}

export interface ListenOptions extends CommonOptions {
    lastEventId?: string | number;
}

export interface WriteResult {
    etag: string | null;
    status: number;
}

export interface DeleteResult {
    status: number;
}

export interface ResponseLike {
    status: number;
    statusText: string;
    headers: Headers;
    body: ArrayBuffer;
}

export interface HeadResult {
    etag: string | null;
    contentType: string | null;
    size: number | null;
    headers: Record<string, string>;
}

export interface GetMetaResult {
    body: string | ArrayBuffer;
    etag: string | null;
    contentType: string;
    size: number | null;
    contentRange: string | null;
    status: number;
}

export type ListenEventType = "put" | "post" | "delete" | "lag" | "message" | "error";

export interface ListenEvent {
    type: ListenEventType;
    id?: string;
    path?: string;
    method?: string;
    etag?: string;
    data?: string;
    error?: unknown;
}

export type Unsubscribe = () => void;

export class ElastikError extends Error {
    constructor(status: number, statusText: string, path: string, body?: string);
    status: number;
    statusText: string;
    path: string;
    body: string;
}

export class NotModified extends ElastikError {}
export class Unauthorized extends ElastikError {}
export class Forbidden extends ElastikError {}
export class NotFound extends ElastikError {}
export class PreconditionFailed extends ElastikError {}
export class PayloadTooLarge extends ElastikError {}
export class ServerError extends ElastikError {}
export class InsufficientStorage extends ServerError {}
export class NetworkError extends ElastikError {}

export class Elastik {
    static start(): unknown;
    constructor(url: string, options?: ElastikOptions);

    url: string;
    writeToken: string;
    readToken: string;
    approveToken: string;
    fetch: FetchLike;

    put(path: string, body: RequestBody, options?: PutOptions): Promise<WriteResult>;
    putText(path: string, text: string, options?: PutOptions): Promise<WriteResult>;
    putJson(path: string, value: unknown, options?: PutOptions): Promise<WriteResult>;

    get(path: string, options: GetMetaOptions): Promise<GetMetaResult>;
    get(path: string, options?: GetOptions): Promise<string | ArrayBuffer>;
    getText(path: string, options?: GetOptions): Promise<string>;
    getJson<T = unknown>(path: string, options?: GetOptions): Promise<T>;

    head(path: string, options?: HeadOptions): Promise<HeadResult>;
    post(path: string, body: RequestBody, options?: PostOptions): Promise<WriteResult>;
    delete(path: string, options?: DeleteOptions): Promise<DeleteResult>;
    request(method: string, path: string, options?: RequestOptions): Promise<ResponseLike>;

    listen(path: string, callback: (event: ListenEvent) => void, options?: ListenOptions): Unsubscribe;

    exists(path: string): Promise<boolean>;
    list(prefix?: string): Promise<string[]>;
    sizeof(path: string): Promise<number>;
    checksum(path: string): Promise<string>;
    isAudited(path: string): Promise<boolean>;
    verify(path: string): Promise<boolean>;
    version(): Promise<string>;
    worlds(): Promise<string>;
}
