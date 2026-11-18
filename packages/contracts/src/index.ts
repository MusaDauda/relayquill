import { DOMAIN_PACKAGE_VERSION } from "@relayquill/domain";

export const CONTRACTS_PACKAGE_VERSION = "0.1.0" as const;

export interface ContractHandshake {
  readonly contractsVersion: typeof CONTRACTS_PACKAGE_VERSION;
  readonly domainVersion: typeof DOMAIN_PACKAGE_VERSION;
}

export function getContractHandshake(): ContractHandshake {
  return {
    contractsVersion: CONTRACTS_PACKAGE_VERSION,
    domainVersion: DOMAIN_PACKAGE_VERSION
  };
}
