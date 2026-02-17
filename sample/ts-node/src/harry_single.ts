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

const create_verify_data = async (): Promise<void> => {
    const keyPair = await new Bls12381G2KeyPair(keyPairOptions);
    let suite = new BbsBlsSignature2020({ key: keyPair });
    let messages = constants["messages"].map((x) => Buffer.from(x, "base64"));

    console.log("Input document");
    console.log(JSON.stringify(inputDocument, null, 2));

    let verify_data = await suite.createVerifyDocumentData(inputDocument, {
        documentLoader,
    });
    console.log(verify_data);
};

const canonize = async (): Promise<void> => {
    //Import the example key pair
    const keyPair = await new Bls12381G2KeyPair(keyPairOptions);
    let suite = new BbsBlsSignature2020({ key: keyPair });
    let messages = constants["messages"].map((x) => Buffer.from(x, "base64"));

    console.log("Input document");
    console.log(JSON.stringify(inputDocument, null, 2));
    //
    let c = await suite.canonize(inputDocument, { documentLoader });
    //
    console.log("canonized document");
    console.log(c);
};

const get = async (): Promise<void> => {
    console.log("get");
    let result = await jsonld.get("https://w3id.org/security/bbs/v1", { documentLoader })
    console.log(JSON.stringify(result, null, 2))

    let expected = bbsContext
    console.log(JSON.stringify(expected, null, 2))

    console.log(result["document"] == expected)
}

const expand = async (): Promise<void> => {
    console.log("expanded input doc");
    let expanded = await jsonld.expand(inputDocument, { documentLoader });
    console.log(JSON.stringify(expanded, null, 2));
}

const toRdf = async (): Promise<void> => {
    console.log("toRDF dataset (raw):");
    let dataset = await jsonld.toRDF(inputDocument, { documentLoader });
    console.log(JSON.stringify(dataset, null, 2));

    console.log("\ntoRDF n-quads:");
    let nquads = await jsonld.toRDF(inputDocument, { documentLoader, format: "application/n-quads" });
    console.log(nquads);
}

const canonize_proof_and_verify_proof_data = async (): Promise<void> => {
    const keyPair = await new Bls12381G2KeyPair(keyPairOptions);
    let suite = new BbsBlsSignature2020({ key: keyPair });

    // Same proof as Rust test_canonize_proof / test_create_verify_proof_data
    const proof = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/citizenship/v1",
            "https://w3id.org/security/bbs/v1"
        ],
        "type": "BbsBlsSignature2020",
        "created": "2026-02-14T23:50:05Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "ju+gk1jtkQpl+1Xx8pLkk1qG1S48Y/8/m7LmGy9OfHDWz7CQoBcrkxVUfE+2z5qsYUHlKfzccE4m7waZyoLEkBLFiK2g54Q2i+CdtYBgDdkUDsoULSBMcH1MwGHwdjfXpldFNFrHFx/IAvLVniyeMQ==",
        "verificationMethod": "did:example:489398593#test"
    };

    console.log("=== canonizeProof ===");
    let canonized = await suite.canonizeProof(proof, { documentLoader });
    console.log(JSON.stringify(canonized));

    console.log("\n=== createVerifyProofData ===");
    let proofData = await suite.createVerifyProofData(proof, { documentLoader });
    console.log(JSON.stringify(proofData));
};

const sign_and_verify = async (): Promise<void> => {
    const keyPair = await new Bls12381G2KeyPair(keyPairOptions);
    const suite = new BbsBlsSignature2020({ key: keyPair });

    console.log("=== SIGN ===");
    const signedDocument = await sign(inputDocument, {
        suite,
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });
    console.log("Signed document:");
    console.log(JSON.stringify(signedDocument, null, 2));

    // Inspect the proof structure
    const proof = signedDocument.proof;
    console.log("\n=== PROOF DETAILS ===");
    console.log("proof.type:", proof.type);
    console.log("proof.proofPurpose:", proof.proofPurpose);
    console.log("proof.verificationMethod:", proof.verificationMethod);
    console.log("proof.created:", proof.created);
    console.log("proof.proofValue length:", proof.proofValue?.length);
    console.log("proof keys:", Object.keys(proof));

    // Get createVerifyData with the CORRECT inputs (doc without proof)
    console.log("\n=== CREATE VERIFY DATA (doc without proof) ===");
    const { proof: _p, ...docWithoutProof } = signedDocument;
    const verifyData: any = await (suite as any).createVerifyData({
        document: docWithoutProof,
        proof: proof,
        documentLoader,
        compactProof: false,
    });
    console.log("verifyData type:", typeof verifyData);
    console.log("verifyData length:", Array.isArray(verifyData) ? verifyData.length : "N/A");
    console.log("verifyData:", JSON.stringify(verifyData, null, 2));

    // Also get the separate proof/document data
    console.log("\n=== SEPARATE PROOF + DOCUMENT DATA ===");
    const proofData = await (suite as any).createVerifyProofData(proof, { documentLoader });
    const docData = await (suite as any).createVerifyDocumentData(docWithoutProof, { documentLoader });
    console.log("proofData (from signed doc proof, no @context):", JSON.stringify(proofData));
    console.log("proofData.length:", proofData.length);
    console.log("docData.length:", docData.length);

    // Now test with a proof that HAS @context (like during the sign flow)
    const proofWithContext = {
        ...proof,
        "@context": [
            { sec: "https://w3id.org/security#", proof: { "@id": "sec:proof", "@type": "@id", "@container": "@graph" } },
            "https://w3id.org/security/bbs/v1"
        ]
    };
    const proofDataWithCtx = await (suite as any).createVerifyProofData(proofWithContext, { documentLoader });
    console.log("proofData (with @context):", JSON.stringify(proofDataWithCtx));
    console.log("proofData.length (with @context):", proofDataWithCtx.length);

    // What does createVerifyData return when proof has @context?
    const verifyDataWithCtx: any = await (suite as any).createVerifyData({
        document: docWithoutProof,
        proof: proofWithContext,
        documentLoader,
        compactProof: false,
    });
    console.log("\nverifyData (with proof @context) length:", verifyDataWithCtx.length);
    if (typeof verifyDataWithCtx === 'object' && verifyDataWithCtx.proof) {
        console.log("verifyData.proof:", JSON.stringify(verifyDataWithCtx.proof));
        console.log("verifyData.document length:", verifyDataWithCtx.document?.length);
    } else {
        console.log("verifyData (flat):", JSON.stringify(verifyDataWithCtx));
    }

    console.log("\n=== VERIFY ===");
    const verified = await verify(signedDocument, {
        suite: new BbsBlsSignature2020(),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
    });
    console.log("Verification result:");
    console.log(JSON.stringify(verified, null, 2));
};

const main = async (): Promise<void> => {
    await sign_and_verify();
};

main();
