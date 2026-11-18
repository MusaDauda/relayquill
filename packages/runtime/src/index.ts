import { getContractHandshake, type ContractHandshake } from "@relayquill/contracts";

export const RUNTIME_PACKAGE_VERSION = "0.1.0" as const;

export interface RuntimeIdentity extends ContractHandshake {
  readonly runtimeVersion: typeof RUNTIME_PACKAGE_VERSION;
  readonly platform: NodeJS.Platform;
}

export function getRuntimeIdentity(): RuntimeIdentity {
  return {
    ...getContractHandshake(),
    runtimeVersion: RUNTIME_PACKAGE_VERSION,
    platform: process.platform
  };
}
