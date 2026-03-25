declare module 'cli-table3' {
  export default class Table {
    constructor(options?: Record<string, unknown>);
    push(...rows: unknown[]): number;
    toString(): string;
  }
}

declare module 'x402-stacks' {
  import type { AxiosInstance } from 'axios';

  export function privateKeyToAccount(
    privateKey: string,
    network: 'mainnet' | 'testnet'
  ): unknown;

  export function wrapAxiosWithPayment(
    client: AxiosInstance,
    account: unknown,
    config?: Record<string, unknown>
  ): AxiosInstance;
}
