import { type Temporal } from "@js-temporal/polyfill";
import type { Base64UrlString, WEBHOOK_HEADER_NAMES } from "@relayquill/contracts";
import type { Sha256Hex } from "@relayquill/domain";
import {
  type EndpointKeyMetadata,
  type SigningKeyHandle,
  type VerifyEndpointVerificationSuccess,
  signEndpointProof
} from "@relayquill/signing";
import { toReceiverSdkError } from "./errors.js";
import {
  type ReceiverKeyResolverInput,
  withResolvedSigningMaterial
} from "./keys.js";

export type { Base64UrlString };

export interface EndpointProofResponseWriter {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(): unknown;
}

export interface HandleEndpointProofChallengeInput {
  readonly verifiedRequest: VerifyEndpointVerificationSuccess;
  readonly keyHandle?: SigningKeyHandle | undefined;
  readonly keyMetadata?: EndpointKeyMetadata | undefined;
  readonly keyProvider?: ReceiverKeyResolverInput | undefined;
  readonly now?: Temporal.Instant | undefined;
  readonly response?: EndpointProofResponseWriter | undefined;
}

export interface EndpointProofHttpResponse {
  readonly statusCode: 204;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
  readonly headerName: typeof WEBHOOK_HEADER_NAMES.endpointProof;
  readonly headerValue: string;
  readonly proofSha256: Sha256Hex;
}

export async function handleEndpointProofChallenge(
  input: HandleEndpointProofChallengeInput
): Promise<EndpointProofHttpResponse> {
  const { verifiedRequest } = input;
  const { verificationBody, headers, verifiedKeyId, bodySha256 } = verifiedRequest;

  const signed = await withResolvedSigningMaterial(
    {
      keyHandle: input.keyHandle,
      keyMetadata: input.keyMetadata,
      keyProvider: input.keyProvider,
      projectId: headers.project_id,
      endpointId: verificationBody.endpoint_id,
      keyId: verifiedKeyId,
      purpose: "endpoint_verification"
    },
    (material) => {
      try {
        return signEndpointProof({
          verificationIntentId: verificationBody.verification_id,
          endpointId: verificationBody.endpoint_id,
          endpointVersion: verificationBody.endpoint_version,
          configurationSha256: verificationBody.configuration_sha256,
          keyId: verifiedKeyId,
          publicNonce: verificationBody.public_nonce,
          verificationAttemptId: headers.attempt_id,
          requestTimestampSeconds: headers.timestamp_seconds,
          requestWireBodySha256: bodySha256,
          keyHandle: material.handle,
          keyMetadata: material.metadata,
          now: input.now
        });
      } catch (err) {
        throw toReceiverSdkError(err);
      }
    }
  );

  if (input.response !== undefined) {
    input.response.statusCode = 204;
    input.response.setHeader(signed.headerName, signed.headerValue);
    input.response.end();
  }

  return Object.freeze({
    statusCode: 204,
    headers: Object.freeze({
      [signed.headerName]: signed.headerValue
    }),
    body: new Uint8Array(0),
    headerName: signed.headerName,
    headerValue: signed.headerValue,
    proofSha256: signed.proofSha256
  });
}
