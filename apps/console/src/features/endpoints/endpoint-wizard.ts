import { type SignatureMode } from "@relayquill/domain";

export type EndpointWizardStep = 1 | 2 | 3 | 4 | 5 | 6;

export interface EndpointWizardDraft {
  readonly name: string;
  readonly destinationUrl: string;
  readonly senderCustodyRefId: string;
  readonly receiverCustodyRefId: string;
  readonly keyIdLabel: string;
  readonly signatureMode: SignatureMode;
  readonly receiverContractId: string;
  readonly receiverContractVersion: string;
  readonly receiverReadinessAck: boolean;
}

export interface EndpointWizardState {
  readonly currentStep: EndpointWizardStep;
  readonly draft: EndpointWizardDraft;
  readonly endpointId: string | null;
  readonly endpointVersion: string | null;
  readonly configurationSha256: string | null;
  readonly normalizedHost: string | null;
  readonly keyVersionId: string | null;
  readonly signingPolicyId: string | null;
  readonly verificationIntentId: string | null;
  readonly verificationPassed: boolean;
  readonly verificationProofSha256: string | null;
  readonly activated: boolean;
}

export const ENDPOINT_WIZARD_STEP_LABELS: readonly {
  readonly step: EndpointWizardStep;
  readonly title: string;
  readonly description: string;
}[] = [
  {
    step: 1,
    title: "1. Normalized Destination",
    description: "Register endpoint name and pinned HTTPS URL."
  },
  {
    step: 2,
    title: "2. Dual-Custody Secret Refs",
    description: "Create key intent using protected custody destination references."
  },
  {
    step: 3,
    title: "3. Readiness & Policy",
    description: "Confirm receiver contract readiness and bind signing policy."
  },
  {
    step: 4,
    title: "4. Bounded Verification Proof",
    description: "Run bounded HTTPS 204 / HMAC probe against pinned destination."
  },
  {
    step: 5,
    title: "5. Pre-Activation Review",
    description: "Inspect configuration digest and verification proof."
  },
  {
    step: 6,
    title: "6. Activation",
    description: "Promote verified endpoint version to active dispatch state."
  }
];

export function createInitialEndpointWizardState(): EndpointWizardState {
  return {
    currentStep: 1,
    draft: {
      name: "",
      destinationUrl: "",
      senderCustodyRefId: "custody-sender-primary",
      receiverCustodyRefId: "custody-receiver-primary",
      keyIdLabel: "rk_v1_primary",
      signatureMode: "primary_only",
      receiverContractId: "",
      receiverContractVersion: "1",
      receiverReadinessAck: false
    },
    endpointId: null,
    endpointVersion: null,
    configurationSha256: null,
    normalizedHost: null,
    keyVersionId: null,
    signingPolicyId: null,
    verificationIntentId: null,
    verificationPassed: false,
    verificationProofSha256: null,
    activated: false
  };
}

export function validateNormalizedHttpsUrl(rawUrl: string): {
  readonly valid: boolean;
  readonly normalizedUrl?: string | undefined;
  readonly normalizedHost?: string | undefined;
  readonly reason?: string | undefined;
} {
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) {
    return { valid: false, reason: "Destination URL is required." };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, reason: "Destination URL is not a valid absolute URL." };
  }
  if (parsed.protocol !== "https:") {
    return { valid: false, reason: "Production destination URLs must use https://." };
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    return { valid: false, reason: "Embedded credentials in URL userinfo are forbidden." };
  }
  if (parsed.hash.length > 0) {
    return { valid: false, reason: "URL fragments (#...) are not permitted in webhook destinations." };
  }
  const host = parsed.hostname.toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]" || host.endsWith(".local")) {
    return { valid: false, reason: `Loopback or local host "${host}" is forbidden by egress URL policy.` };
  }
  return {
    valid: true,
    normalizedUrl: parsed.toString(),
    normalizedHost: host
  };
}

export function validateCustodyReferenceId(refId: string, label: string): string | null {
  const trimmed = refId.trim();
  if (trimmed.length < 3 || trimmed.length > 128) {
    return `${label} must be 3..128 characters.`;
  }
  if (/\s/.test(trimmed)) {
    return `${label} must be an opaque reference ID without whitespace.`;
  }
  if (/-----BEGIN|rq_p1\.|whsec_|sk_live_|sk_test_|password=/i.test(trimmed)) {
    return `${label} appears to contain a raw secret; supply only an external custody reference ID.`;
  }
  return null;
}

/**
 * Updating upstream identity fields invalidates downstream verification/policy artifacts so stale
 * verification proofs cannot activate modified destinations or signing keys.
 */
export function updateEndpointWizardDraft(
  state: EndpointWizardState,
  patch: Partial<EndpointWizardDraft>
): EndpointWizardState {
  const nextDraft: EndpointWizardDraft = { ...state.draft, ...patch };
  const urlChanged =
    patch.destinationUrl !== undefined && patch.destinationUrl !== state.draft.destinationUrl;
  const custodyChanged =
    (patch.senderCustodyRefId !== undefined &&
      patch.senderCustodyRefId !== state.draft.senderCustodyRefId) ||
    (patch.receiverCustodyRefId !== undefined &&
      patch.receiverCustodyRefId !== state.draft.receiverCustodyRefId) ||
    (patch.keyIdLabel !== undefined && patch.keyIdLabel !== state.draft.keyIdLabel);
  const policyChanged =
    (patch.signatureMode !== undefined && patch.signatureMode !== state.draft.signatureMode) ||
    (patch.receiverContractId !== undefined &&
      patch.receiverContractId !== state.draft.receiverContractId) ||
    (patch.receiverContractVersion !== undefined &&
      patch.receiverContractVersion !== state.draft.receiverContractVersion) ||
    (patch.receiverReadinessAck !== undefined &&
      patch.receiverReadinessAck !== state.draft.receiverReadinessAck);

  if (urlChanged) {
    return {
      ...state,
      draft: nextDraft,
      endpointId: null,
      endpointVersion: null,
      configurationSha256: null,
      normalizedHost: null,
      keyVersionId: null,
      signingPolicyId: null,
      verificationIntentId: null,
      verificationPassed: false,
      verificationProofSha256: null,
      activated: false,
      currentStep: state.currentStep > 1 ? 1 : state.currentStep
    };
  }

  if (custodyChanged) {
    return {
      ...state,
      draft: nextDraft,
      keyVersionId: null,
      signingPolicyId: null,
      verificationIntentId: null,
      verificationPassed: false,
      verificationProofSha256: null,
      activated: false,
      currentStep: state.currentStep > 2 ? 2 : state.currentStep
    };
  }

  if (policyChanged) {
    return {
      ...state,
      draft: nextDraft,
      signingPolicyId: null,
      verificationIntentId: null,
      verificationPassed: false,
      verificationProofSha256: null,
      activated: false,
      currentStep: state.currentStep > 3 ? 3 : state.currentStep
    };
  }

  return {
    ...state,
    draft: nextDraft
  };
}

export function getEndpointWizardStepEligibility(
  state: EndpointWizardState,
  targetStep: EndpointWizardStep
): { readonly allowed: boolean; readonly reason: string | null } {
  if (targetStep === 1) {
    return { allowed: true, reason: null };
  }
  if (targetStep >= 2 && state.endpointId === null) {
    return { allowed: false, reason: "Step 1 must register and persist the endpoint draft first." };
  }
  if (targetStep >= 3 && state.keyVersionId === null) {
    return {
      allowed: false,
      reason: "Step 2 must create dual-custody signing key references first."
    };
  }
  if (targetStep >= 4 && (!state.draft.receiverReadinessAck || state.signingPolicyId === null)) {
    return {
      allowed: false,
      reason: "Step 3 must confirm receiver readiness and bind an active signing policy first."
    };
  }
  if (targetStep >= 5 && !state.verificationPassed) {
    return {
      allowed: false,
      reason: "Step 4 bounded HTTP 204/HMAC verification proof must succeed before review."
    };
  }
  if (targetStep >= 6 && state.verificationProofSha256 === null) {
    return {
      allowed: false,
      reason: "Verification digest is required before step 6 activation."
    };
  }
  return { allowed: true, reason: null };
}

export function transitionEndpointWizardStep(
  state: EndpointWizardState,
  targetStep: EndpointWizardStep
): EndpointWizardState {
  const check = getEndpointWizardStepEligibility(state, targetStep);
  if (!check.allowed) {
    return state;
  }
  return {
    ...state,
    currentStep: targetStep
  };
}
