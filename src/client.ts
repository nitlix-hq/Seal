import deriveIKP from "./func/deriveIKP";
import deriveUK from "./func/deriveUK";
import generateCK from "./func/generateCK";
import generateKeyPair from "./func/generateKeyPair";
import generateSeedphrase from "./func/generateSeedphrase";
import { decryptContentWithCK, encryptContentWithCK } from "./lib/content";
import { unwrapCKPUIKInPRIK, wrapCKInPUIK } from "./lib/puikWrap";
import { importUKKeyFromBase64, unwrapCKUK, wrapCKWithUK } from "./lib/wrap";
import { base64ToBytes, bytesToBase64, toArrayBuffer } from "./lib/bytes";
import {
    GCM_IV_LENGTH,
    IDENTITY_DB_NAME,
    IDENTITY_KDF_ALG,
    IDENTITY_KEM_ALG,
    IDENTITY_RECORD_ID,
    IDENTITY_RECORD_VERSION,
    IDENTITY_STORE_NAME,
    SYMMETRIC_WRAP_ALGORITHM,
} from "./vars";

type IdentityRecord = {
    id: string;
    v: number;
    uk: CryptoKey;
    prikWrapped: {
        iv: ArrayBuffer;
        ct: ArrayBuffer;
    };
    puik?: ArrayBuffer;
    alg: {
        wrap: string;
        kem: string;
        kdf: string;
    };
};

/** Throws when IndexedDB is unavailable in the current runtime. */
function ensureIndexedDBAvailable() {
    if (typeof (globalThis as any).indexedDB === "undefined") {
        throw new Error("IndexedDB is unavailable in this runtime.");
    }
}

/** Overwrites a byte array in place to reduce key-material lifetime in memory. */
function zero(bytes: Uint8Array) {
    bytes.fill(0);
}

/** Normalizes an ArrayBuffer-like input into a Uint8Array view. */
function toBytes(input: ArrayBuffer | Uint8Array): Uint8Array {
    return input instanceof Uint8Array ? input : new Uint8Array(input);
}

/** Opens the identity IndexedDB database and creates the store on first use. */
async function openIdentityDB(): Promise<any> {
    ensureIndexedDBAvailable();

    return new Promise((resolve, reject) => {
        const request = (globalThis as any).indexedDB.open(IDENTITY_DB_NAME, 1);

        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
                db.createObjectStore(IDENTITY_STORE_NAME, { keyPath: "id" });
            }
        };

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/** Persists the current identity record to IndexedDB. */
async function putIdentityRecord(record: IdentityRecord): Promise<void> {
    const db = await openIdentityDB();

    await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(IDENTITY_STORE_NAME, "readwrite");
        const store = tx.objectStore(IDENTITY_STORE_NAME);
        store.put(record);

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
    });

    db.close();
}

/** Loads the current identity record from IndexedDB if present. */
async function getIdentityRecord(): Promise<IdentityRecord | null> {
    const db = await openIdentityDB();

    const record = await new Promise<IdentityRecord | null>((resolve, reject) => {
        const tx = db.transaction(IDENTITY_STORE_NAME, "readonly");
        const store = tx.objectStore(IDENTITY_STORE_NAME);
        const request = store.get(IDENTITY_RECORD_ID);

        request.onsuccess = () => resolve((request.result as IdentityRecord) ?? null);
        request.onerror = () => reject(request.error);
    });

    db.close();
    return record;
}

/** Deletes the current identity record from IndexedDB. */
async function deleteIdentityRecord(): Promise<void> {
    const db = await openIdentityDB();

    await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(IDENTITY_STORE_NAME, "readwrite");
        const store = tx.objectStore(IDENTITY_STORE_NAME);
        store.delete(IDENTITY_RECORD_ID);

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
    });

    db.close();
}

export default class SealClient {
    public UK: string;
    public PRIK: string;
    private ukKey?: CryptoKey;

    /** Creates a client with optional in-memory UK and PRIK values. */
    public constructor(
        { UK = "", PRIK = "" }: { UK?: string; PRIK?: string } = {},
    ) {
        this.UK = UK;
        this.PRIK = PRIK;
    }

    /** Initializes client keys from IndexedDB and returns availability flags. */
    public async initialise(): Promise<{
        UK: boolean;
        PRIK: boolean;
        PUIK?: string;
    }> {
        const record = await getIdentityRecord();

        if (!record || !record.uk || !record.prikWrapped) {
            await deleteIdentityRecord();
            this.ukKey = undefined;
            this.PRIK = "";
            this.UK = "";

            return {
                UK: false,
                PRIK: false,
            };
        }

        try {
            const prikBytes = new Uint8Array(
                await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: toArrayBuffer(toBytes(record.prikWrapped.iv)),
                    },
                    record.uk,
                    record.prikWrapped.ct,
                ),
            );

            this.ukKey = record.uk;
            this.UK = "";
            this.PRIK = bytesToBase64(prikBytes);

            zero(prikBytes);

            return {
                UK: true,
                PRIK: true,
                ...(record.puik ? { PUIK: bytesToBase64(toBytes(record.puik)) } : {}),
            };
        } catch {
            await deleteIdentityRecord();
            this.ukKey = undefined;
            this.UK = "";
            this.PRIK = "";

            return {
                UK: false,
                PRIK: false,
            };
        }
    }

    /** Stores UK and UK(PRIK) in IndexedDB and updates in-memory key state. */
    public async writeoff({
        UK,
        PRIK,
        PUIK,
    }: {
        UK: string;
        PRIK: string;
        PUIK?: string;
    }): Promise<{ stored: true }> {
        const ukBytes = base64ToBytes(UK);
        const prikBytes = base64ToBytes(PRIK);

        try {
            const uk = await importUKKeyFromBase64(UK);
            const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_LENGTH));
            const ct = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: toArrayBuffer(iv),
                },
                uk,
                toArrayBuffer(prikBytes),
            );

            let puikBuffer: ArrayBuffer | undefined;
            if (PUIK) {
                puikBuffer = toArrayBuffer(base64ToBytes(PUIK));
            }

            await putIdentityRecord({
                id: IDENTITY_RECORD_ID,
                v: IDENTITY_RECORD_VERSION,
                uk,
                prikWrapped: {
                    iv: toArrayBuffer(iv),
                    ct: ct as ArrayBuffer,
                },
                puik: puikBuffer,
                alg: {
                    wrap: SYMMETRIC_WRAP_ALGORITHM,
                    kem: IDENTITY_KEM_ALG,
                    kdf: IDENTITY_KDF_ALG,
                },
            });

            this.ukKey = uk;
            this.UK = UK;
            this.PRIK = PRIK;

            return { stored: true };
        } finally {
            zero(ukBytes);
            zero(prikBytes);
        }
    }

    /** Generates a new 24-word seed phrase. */
    public generateSeedphrase(): ReturnType<typeof generateSeedphrase> {
        return generateSeedphrase();
    }

    /** Derives UK from a seed phrase. */
    public deriveUK(seedPhrase: string): ReturnType<typeof deriveUK> {
        return deriveUK(seedPhrase);
    }

    /** Derives PUIK/PRIK from a seed phrase. */
    public deriveIKP(seedPhrase: string): ReturnType<typeof deriveIKP> {
        return deriveIKP(seedPhrase);
    }

    /** Generates a new content key. */
    public generateCK(): ReturnType<typeof generateCK> {
        return generateCK();
    }

    /** Generates a new identity key pair. */
    public generateKeyPair(): ReturnType<typeof generateKeyPair> {
        return generateKeyPair();
    }

    /** Backward-compatible alias for deriving the identity key pair. */
    public deriveIdentityKeyPair(seedPhrase: string): ReturnType<typeof deriveIKP> {
        return deriveIKP(seedPhrase);
    }

    /** Seals CK to a recipient PUIK for sharing. */
    public async wrapInPUIK(
        CK: string,
        PUIK: string,
    ): ReturnType<typeof wrapCKInPUIK> {
        return wrapCKInPUIK({ CK, PUIK });
    }

    /** Encrypts plaintext content with a provided CK. */
    public async encryptWithCK({
        content,
        CK,
    }: {
        content: string;
        CK: string;
    }): ReturnType<typeof encryptContentWithCK> {
        return encryptContentWithCK({ content, CK });
    }

    /** Decrypts ciphertext content with a provided CK. */
    public async decryptWithCK({
        content,
        CK,
    }: {
        content: string;
        CK: string;
    }): ReturnType<typeof decryptContentWithCK> {
        return decryptContentWithCK({ content, CK });
    }

    /** Encrypts content and returns ciphertext plus CK wrapped with UK. */
    public async encryptContent({
        content,
        CK = "",
    }: {
        content: string;
        CK?: string;
    }): Promise<{ "CK-UK": string; ciphertext: string }> {
        const resolvedCK = CK.trim() ? CK : this.generateCK().CK;
        const [{ "CK-UK": CK_UK }, { content: ciphertext }] = await Promise.all([
            this.wrapWithUK(resolvedCK),
            this.encryptWithCK({ content, CK: resolvedCK }),
        ]);

        return {
            "CK-UK": CK_UK,
            ciphertext,
        };
    }

    /** Decrypts content from a CK-UK wrap and ciphertext pair. */
    public async decryptContent({
        "CK-UK": CK_UK,
        ciphertext,
    }: {
        "CK-UK": string;
        ciphertext: string;
    }): ReturnType<typeof decryptContentWithCK> {
        const { CK } = await this.unwrapWithUK(CK_UK);
        return this.decryptWithCK({ content: ciphertext, CK });
    }

    /** Backward-compatible alias for encryptWithCK. */
    public async encrypt({
        content,
        CK,
    }: {
        content: string;
        CK: string;
    }): ReturnType<typeof encryptContentWithCK> {
        return this.encryptWithCK({ content, CK });
    }

    /** Backward-compatible alias for decryptWithCK. */
    public async decrypt({
        content,
        CK,
    }: {
        content: string;
        CK: string;
    }): ReturnType<typeof decryptContentWithCK> {
        return this.decryptWithCK({ content, CK });
    }

    /** Unseals CK from a CK-PUIK payload using the current PRIK. */
    public async unwrapInPRIK(
        CK_PUIK: string,
    ): ReturnType<typeof unwrapCKPUIKInPRIK> {
        return unwrapCKPUIKInPRIK({
            "CK-PUIK": CK_PUIK,
            PRIK: this.PRIK,
        });
    }

    /** Wraps CK with the current UK. */
    public async wrapWithUK(CK: string): ReturnType<typeof wrapCKWithUK> {
        return wrapCKWithUK({ CK, UK: this.UK, ukKey: this.ukKey });
    }

    /** Unwraps CK from a CK-UK payload using the current UK. */
    public async unwrapWithUK(CK_UK: string): ReturnType<typeof unwrapCKUK> {
        return unwrapCKUK({
            "CK-UK": CK_UK,
            UK: this.UK,
            ukKey: this.ukKey,
        });
    }
}
