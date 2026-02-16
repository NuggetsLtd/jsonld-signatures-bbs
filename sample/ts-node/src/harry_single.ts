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

const main = async (): Promise<void> => {
    await expand()
    //Sign the input document
    // const keyPair = await new Bls12381G2KeyPair(keyPairOptions);
    // let suite = new BbsBlsSignature2020({ key: keyPair });
    // const signedDocument = await sign(inputDocument, {
    //     suite,
    //     purpose: new purposes.AssertionProofPurpose(),
    //     documentLoader,
    // });
    // console.log("Input document with proof");
    // console.log(JSON.stringify(signedDocument, null, 2));
    // let x = await suite.createVerifyProofData(with_ctx, { documentLoader })
    //
    // console.log("proofdata");
    // console.log(JSON.stringify(x, null, 2));

    //
    // //Verify the proof
    // let verified = await verify(signedDocument, {
    //   suite: new BbsBlsSignature2020(),
    //   purpose: new purposes.AssertionProofPurpose(),
    //   documentLoader,
    // });
    //
    // console.log("Verification result");
    // console.log(JSON.stringify(verified, null, 2));
    //
    // //Derive a proof
    // const derivedProof = await deriveProof(signedDocument, revealDocument, {
    //   suite: new BbsBlsSignatureProof2020(),
    //   documentLoader,
    // });
    //
    // console.log(JSON.stringify(derivedProof, null, 2));
    //
    // //Verify the derived proof
    // verified = await verify(derivedProof, {
    //   suite: new BbsBlsSignatureProof2020(),
    //   purpose: new purposes.AssertionProofPurpose(),
    //   documentLoader,
    // });
    //
    // console.log("Verification result");
    // console.log(JSON.stringify(verified, null, 2));
};

main();
