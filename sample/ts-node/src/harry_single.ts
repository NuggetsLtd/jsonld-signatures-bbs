// run
// npm run harry

import { Buffer } from "buffer";
import {
    Bls12381G2KeyPair,
    BbsBlsSignature2020,
    BbsBlsSignatureProof2020,
    deriveProof,
} from "@mattrglobal/jsonld-signatures-bbs";
import { extendContextLoader, sign, verify, purposes } from "jsonld-signatures";
import constants from "./data/constants.json";

import inputDocument from "./data/inputDocument.json";
import keyPairOptions from "./data/keyPair.json";
import exampleControllerDoc from "./data/controllerDocument.json";
import bbsContext from "./data/bbs.json";
import revealDocument from "./data/deriveProofFrame.json";
import citizenVocab from "./data/citizenVocab.json";
import credentialContext from "./data/credentialsContext.json";
import suiteContext from "./data/suiteContext.json";

import * as jsonld from "jsonld";

/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
const documents: any = {
    "did:example:489398593#test": keyPairOptions,
    "did:example:489398593": exampleControllerDoc,
    "https://w3id.org/security/bbs/v1": bbsContext,
    "https://w3id.org/citizenship/v1": citizenVocab,
    "https://www.w3.org/2018/credentials/v1": credentialContext,
    "https://w3id.org/security/suites/jws-2020/v1": suiteContext,
};

/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
const customDocLoader = (url: string): any => {
    const context = documents[url];

    if (context) {
        return {
            contextUrl: null, // this is for a context via a link header
            document: context, // this is the actual document that was loaded
            documentUrl: url, // this is the actual context URL after redirects
        };
    }

    console.log(
        `Attempted to remote load context : '${url}', please cache instead`
    );
    throw new Error(
        `Attempted to remote load context : '${url}', please cache instead`
    );
};

//Extended document load that uses local contexts
/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
const documentLoader: any = extendContextLoader(customDocLoader);

/**
 * Cross-verification: Sign with JS reference library.
 * Log output for comparison with NAPI `node test.mjs` output.
 */
const cross_verify_sign = async (): Promise<void> => {
    console.log("=== CROSS-VERIFY: SIGN ===\n");

    const keyPair = await new Bls12381G2KeyPair(keyPairOptions);
    const suite = new BbsBlsSignature2020({ key: keyPair });

    const signedDocument = await sign(inputDocument, {
        suite,
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });

    console.log("JS Reference — Signed document proof:");
    console.log(JSON.stringify(signedDocument.proof, null, 2));

    // Sanity check: verify with JS reference
    const verifyResult = await verify(signedDocument, {
        suite: new BbsBlsSignature2020(),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });

    console.log("\nJS Reference — Verify result:", verifyResult.verified);
    if (!verifyResult.verified) {
        console.log("Error:", JSON.stringify(verifyResult.error, null, 2));
    }
};

/**
 * Cross-verification: Derive selective disclosure proof with JS reference.
 * Log output for comparison with NAPI output.
 */
const cross_verify_derive = async (): Promise<void> => {
    console.log("\n=== CROSS-VERIFY: DERIVE ===\n");

    const keyPair = await new Bls12381G2KeyPair(keyPairOptions);
    const suite = new BbsBlsSignature2020({ key: keyPair });

    // Sign
    const signedDocument = await sign(inputDocument, {
        suite,
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });

    // Derive
    const derivedDocument = await deriveProof(signedDocument, revealDocument, {
        suite: new BbsBlsSignatureProof2020(),
        documentLoader,
    });

    console.log("JS Reference — Derived document:");
    console.log(JSON.stringify(derivedDocument, null, 2));

    // Verify derived
    const verifyResult = await verify(derivedDocument, {
        suite: new BbsBlsSignatureProof2020(),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });

    console.log("\nJS Reference — Derived verify result:", verifyResult.verified);
    if (!verifyResult.verified) {
        console.log("Error:", JSON.stringify(verifyResult.error, null, 2));
    }
};

/**
 * Cross-verification: Full round-trip flow.
 * Sign → Verify → Derive → Verify-derived, all with JS reference.
 * Log structured output for comparison with NAPI bindings.
 */
const cross_verify_round_trip = async (): Promise<void> => {
    console.log("\n=== CROSS-VERIFY: FULL ROUND TRIP ===\n");

    const keyPair = await new Bls12381G2KeyPair(keyPairOptions);

    // Step 1: Sign
    const suite = new BbsBlsSignature2020({ key: keyPair });
    const signedDocument = await sign(inputDocument, {
        suite,
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });
    console.log("Step 1 — Signed proof type:", signedDocument.proof.type);
    console.log("Step 1 — Signed proof keys:", Object.keys(signedDocument.proof));

    // Step 2: Verify
    const verifyResult = await verify(signedDocument, {
        suite: new BbsBlsSignature2020(),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });
    console.log("Step 2 — Verify:", verifyResult.verified);

    // Step 3: Derive
    const derivedDocument = await deriveProof(signedDocument, revealDocument, {
        suite: new BbsBlsSignatureProof2020(),
        documentLoader,
    });
    console.log("Step 3 — Derived proof type:", derivedDocument.proof.type);
    console.log("Step 3 — Derived proof keys:", Object.keys(derivedDocument.proof));
    console.log("Step 3 — Derived document keys:", Object.keys(derivedDocument));

    // Check selective disclosure
    const subject = derivedDocument.credentialSubject;
    if (subject) {
        console.log("Step 3 — credentialSubject keys:", Object.keys(subject));
    }

    // Step 4: Verify derived
    const derivedVerifyResult = await verify(derivedDocument, {
        suite: new BbsBlsSignatureProof2020(),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });
    console.log("Step 4 — Derived verify:", derivedVerifyResult.verified);

    console.log("\n=== ROUND TRIP COMPLETE ===");
};

const main = async (): Promise<void> => {
    await cross_verify_sign();
    await cross_verify_derive();
    await cross_verify_round_trip();
};

main();
