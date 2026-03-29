#!/usr/bin/env node

import { Command } from 'commander';
import axios, { AxiosError, AxiosInstance, AxiosResponse } from 'axios';
import Table from 'cli-table3';
import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import { homedir } from 'os';
import path from 'path';
import { StacksMainnet, StacksTestnet } from '@stacks/network';
import {
  AnchorMode,
  PostConditionMode,
  TransactionVersion,
  bufferCVFromString,
  createStacksPrivateKey,
  getAddressFromPrivateKey,
  makeContractCall,
  makeSTXTokenTransfer,
  noneCV,
  principalCV,
  signMessageHashRsv,
  someCV,
  uintCV,
} from '@stacks/transactions';

type VerificationChecks = {
  signature_valid: boolean;
  principal_match?: boolean;
  payment_txid_confirmed?: boolean;
  bns_verified?: boolean;
};

type ReceiptPayload = {
  receipt_id: string;
  request_hash?: string;
  payment_txid?: string;
  seller_principal?: string;
  delivery_commitment?: string | null;
  timestamp?: number;
  signature?: string;
  [key: string]: unknown;
};

const API_BASE_URL = process.env.STXACT_API_URL || 'http://localhost:3001';
const SUPPORTED_CURL_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

interface CurlCommandOptions {
  method: string;
  header: string[];
  body?: string;
  wallet?: string;
  token?: string;
  output?: string;
  verify?: boolean;
  verbose?: boolean;
}

interface VerifyReceiptCommandOptions {
  response?: string;
  onChain?: boolean;
  bns?: boolean;
}

interface DisputeCreateCommandOptions {
  wallet?: string;
  evidence?: string;
  expectedHash?: string;
  receivedHash?: string;
}

interface DisputeRefundCommandOptions {
  wallet?: string;
}

interface ListServicesCommandOptions {
  minRep?: string;
  category?: string;
  token?: string;
  limit?: string;
  format?: string;
}

type PaymentRequirement = {
  network: string;
  asset: string;
  amount: string;
  payTo: string;
};

type PaymentRequiredResponse = {
  x402Version: number;
  resource?: Record<string, unknown>;
  accepts: PaymentRequirement[];
};

type WalletAccount = {
  address: string;
  privateKey: string;
  network: 'mainnet' | 'testnet';
};

function parseHeaders(headers: string[]): Record<string, string> {
  return headers.reduce<Record<string, string>>((acc, header) => {
    const index = header.indexOf(':');
    if (index === -1) return acc;
    const key = header.slice(0, index).trim();
    const value = header.slice(index + 1).trim();
    if (key && value) acc[key] = value;
    return acc;
  }, {});
}

async function readJsonFile<T>(path: string): Promise<T> {
  const content = await fs.readFile(path, 'utf8');
  return JSON.parse(content) as T;
}

function normalizePrivateKey(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error('Wallet private key is empty');
  }

  return trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed;
}

function resolveUserPath(inputPath: string): string {
  if (inputPath === '~') {
    return homedir();
  }

  if (inputPath.startsWith('~/') || inputPath.startsWith('~\\')) {
    return path.join(homedir(), inputPath.slice(2));
  }

  return inputPath;
}

function extractPrivateKeyFromWalletData(data: unknown): string | null {
  if (!data) return null;

  if (typeof data === 'string') {
    return data.trim() ? normalizePrivateKey(data) : null;
  }

  if (typeof data !== 'object') return null;

  const wallet = data as Record<string, unknown>;
  const directCandidates = [
    wallet.privateKey,
    wallet.private_key,
    wallet.secretKey,
    wallet.secret_key,
    wallet.stxPrivateKey,
    wallet.stx_private_key,
  ];

  for (const candidate of directCandidates) {
    if (typeof candidate === 'string' && candidate.trim()) {
      return normalizePrivateKey(candidate);
    }
  }

  const nestedCandidates = [wallet.account, wallet.accounts, wallet.wallet, wallet.credentials];

  for (const candidate of nestedCandidates) {
    if (Array.isArray(candidate)) {
      for (const item of candidate) {
        const nestedResult = extractPrivateKeyFromWalletData(item);
        if (nestedResult) return nestedResult;
      }
    } else {
      const nestedResult = extractPrivateKeyFromWalletData(candidate);
      if (nestedResult) return nestedResult;
    }
  }

  return null;
}

async function loadWalletPrivateKey(walletPath: string): Promise<string> {
  const resolvedPath = resolveUserPath(walletPath);
  const raw = await fs.readFile(resolvedPath, 'utf8');

  try {
    const parsed = JSON.parse(raw) as unknown;
    const privateKey = extractPrivateKeyFromWalletData(parsed);

    if (!privateKey) {
      throw new Error(
        `No private key field found in wallet file ${resolvedPath}. Expected one of: privateKey, private_key, secretKey`
      );
    }

    return privateKey;
  } catch (error) {
    if (error instanceof SyntaxError) {
      // Support plain-text key files
      return normalizePrivateKey(raw);
    }

    throw error;
  }
}

function getStacksNetwork(): 'mainnet' | 'testnet' {
  const value = (
    process.env.STXACT_STACKS_NETWORK ||
    process.env.STACKS_NETWORK ||
    'testnet'
  ).toLowerCase();

  return value === 'mainnet' ? 'mainnet' : 'testnet';
}

function getHeaderValue(
  headers: AxiosResponse['headers'] | Record<string, unknown> | undefined,
  targetKey: string
): string | undefined {
  if (!headers) return undefined;

  const headersRecord = headers as Record<string, unknown> & {
    get?: (name: string) => unknown;
  };

  if (typeof headersRecord.get === 'function') {
    const direct = headersRecord.get(targetKey);
    if (typeof direct === 'string') return direct;
    if (Array.isArray(direct)) return direct.join(', ');
  }

  const lowerTarget = targetKey.toLowerCase();
  for (const [key, value] of Object.entries(headersRecord)) {
    if (key.toLowerCase() !== lowerTarget) continue;
    if (typeof value === 'string') return value;
    if (typeof value === 'number') return String(value);
    if (Array.isArray(value)) return value.map((item) => String(item)).join(', ');
  }

  return undefined;
}

function sha256HexFromUnknownPayload(payload: unknown): string {
  if (Buffer.isBuffer(payload)) {
    return createHash('sha256').update(payload).digest('hex');
  }

  if (typeof payload === 'string') {
    return createHash('sha256').update(Buffer.from(payload, 'utf8')).digest('hex');
  }

  const serialized = JSON.stringify(payload ?? null);
  return createHash('sha256').update(Buffer.from(serialized, 'utf8')).digest('hex');
}

function decodeReceiptFromHeader(receiptHeader: string | undefined): ReceiptPayload | null {
  if (!receiptHeader) return null;

  try {
    const decoded = Buffer.from(receiptHeader, 'base64').toString('utf8');
    return JSON.parse(decoded) as ReceiptPayload;
  } catch {
    return null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function getWalletAccount(privateKey: string): WalletAccount {
  const network = getStacksNetwork();
  const transactionVersion =
    network === 'mainnet' ? TransactionVersion.Mainnet : TransactionVersion.Testnet;

  return {
    address: getAddressFromPrivateKey(privateKey, transactionVersion),
    privateKey,
    network,
  };
}

function getConfiguredStacksApiUrl(network: 'mainnet' | 'testnet'): string | undefined {
  if (process.env.STXACT_STACKS_API_URL) {
    return process.env.STXACT_STACKS_API_URL;
  }

  const sharedOverride = process.env.STACKS_API_URL;
  if (sharedOverride) {
    return sharedOverride;
  }

  return network === 'mainnet'
    ? process.env.STXACT_STACKS_MAINNET_API_URL
    : process.env.STXACT_STACKS_TESTNET_API_URL;
}

function createStacksNetworkClient(network: 'mainnet' | 'testnet') {
  const apiUrl = getConfiguredStacksApiUrl(network);
  if (network === 'mainnet') {
    return new StacksMainnet(apiUrl ? { url: apiUrl } : undefined);
  }

  return new StacksTestnet(apiUrl ? { url: apiUrl } : undefined);
}

function parsePaymentRequiredResponse(response: AxiosResponse): PaymentRequiredResponse | null {
  const headerValue = getHeaderValue(response.headers, 'payment-required');
  if (headerValue) {
    try {
      const decoded = Buffer.from(headerValue, 'base64').toString('utf8');
      return JSON.parse(decoded) as PaymentRequiredResponse;
    } catch {
      return null;
    }
  }

  if (
    response.data &&
    typeof response.data === 'object' &&
    (response.data as PaymentRequiredResponse).x402Version === 2 &&
    Array.isArray((response.data as PaymentRequiredResponse).accepts)
  ) {
    return response.data as PaymentRequiredResponse;
  }

  return null;
}

function normalizeAssetSymbol(asset: string): 'STX' | 'SBTC' | 'USDCX' | 'UNKNOWN' {
  const normalized = asset.toUpperCase();

  if (normalized === 'STX' || normalized.includes(':SLIP44:5757')) {
    return 'STX';
  }

  if (normalized.includes('SBTC') || normalized.includes('/SBTC') || normalized.includes(':BTC')) {
    return 'SBTC';
  }

  if (normalized.includes('USDCX') || normalized.includes('/USDCX')) {
    return 'USDCX';
  }

  return 'UNKNOWN';
}

function selectPaymentRequirement(
  paymentRequired: PaymentRequiredResponse,
  account: WalletAccount,
  preferredToken: string | undefined
): PaymentRequirement | null {
  const preferredAsset = preferredToken?.trim().toUpperCase();

  const compatibleOptions = paymentRequired.accepts.filter((option) => {
    const optionNetwork =
      option.network === 'stacks:1'
        ? 'mainnet'
        : option.network === 'stacks:2147483648'
          ? 'testnet'
          : null;

    return optionNetwork === account.network;
  });

  if (!compatibleOptions.length) {
    return null;
  }

  if (!preferredAsset) {
    return compatibleOptions[0];
  }

  return (
    compatibleOptions.find((option) => normalizeAssetSymbol(option.asset) === preferredAsset) ||
    compatibleOptions[0]
  );
}

function getDefaultTokenContract(
  asset: 'SBTC' | 'USDCX',
  network: 'mainnet' | 'testnet'
): { address: string; name: string } {
  if (asset === 'SBTC') {
    return network === 'mainnet'
      ? { address: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4', name: 'sbtc-token' }
      : { address: 'ST1F7QA2MDF17S807EPA36TSS8AMEFY4KA9TVGWXT', name: 'sbtc-token' };
  }

  return network === 'mainnet'
    ? { address: 'SP120SBRBQJ00MCWS7TM5R8WJNTTKD5K0HFRC2CNE', name: 'usdcx' }
    : { address: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM', name: 'usdcx' };
}

async function signPaymentRequirement(
  requirement: PaymentRequirement,
  account: WalletAccount
): Promise<string> {
  const network = createStacksNetworkClient(account.network);
  const amount = BigInt(requirement.amount);
  const asset = normalizeAssetSymbol(requirement.asset);
  const memo = `x402:${Date.now().toString(36)}`.slice(0, 34);

  if (asset === 'STX') {
    const transaction = await makeSTXTokenTransfer({
      recipient: requirement.payTo,
      amount,
      senderKey: account.privateKey,
      network,
      memo,
      anchorMode: AnchorMode.Any,
    });

    return Buffer.from(transaction.serialize()).toString('hex');
  }

  if (asset === 'SBTC' || asset === 'USDCX') {
    const tokenContract = getDefaultTokenContract(asset, account.network);
    const transaction = await makeContractCall({
      contractAddress: tokenContract.address,
      contractName: tokenContract.name,
      functionName: 'transfer',
      functionArgs: [
        uintCV(amount.toString()),
        principalCV(account.address),
        principalCV(requirement.payTo),
        memo ? someCV(bufferCVFromString(memo)) : noneCV(),
      ],
      senderKey: account.privateKey,
      network,
      anchorMode: AnchorMode.Any,
      postConditionMode: PostConditionMode.Allow,
    });

    return Buffer.from(transaction.serialize()).toString('hex');
  }

  throw new Error(`Unsupported payment asset "${requirement.asset}"`);
}

async function executePaymentRetry(
  client: AxiosInstance,
  url: string,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  response402: AxiosResponse,
  walletPath: string,
  token: string | undefined,
  verbose: boolean
): Promise<AxiosResponse> {
  const paymentRequired = parsePaymentRequiredResponse(response402);
  if (!paymentRequired) {
    throw new Error('Server returned 402 without a valid x402 payment request');
  }

  const privateKey = await loadWalletPrivateKey(walletPath);
  const account = getWalletAccount(privateKey);
  const selectedRequirement = selectPaymentRequirement(paymentRequired, account, token);

  if (!selectedRequirement) {
    throw new Error(
      `No compatible payment option found for ${account.network}. Available networks: ${paymentRequired.accepts
        .map((option) => option.network)
        .join(', ')}`
    );
  }

  const signedTransaction = await signPaymentRequirement(selectedRequirement, account);
  const paymentPayload = {
    x402Version: 2,
    resource: paymentRequired.resource,
    accepted: selectedRequirement,
    payload: {
      transaction: signedTransaction,
    },
  };

  const paymentHeaders = {
    ...headers,
    'payment-signature': Buffer.from(JSON.stringify(paymentPayload)).toString('base64'),
  };

  if (verbose) {
    console.error(`retrying with x402 payment (${normalizeAssetSymbol(selectedRequirement.asset)})`);
  }

  return executeRequestWithRetry(
    () =>
      client.request({
        method,
        url,
        headers: paymentHeaders,
        data: body,
      }),
    method,
    paymentHeaders,
    verbose
  );
}

function hasIdempotencyKey(headers: Record<string, string>): boolean {
  return Object.keys(headers).some((key) => key.toLowerCase() === 'x-idempotency-key');
}

function shouldRetryFiveXX(method: string, headers: Record<string, string>): boolean {
  const normalizedMethod = method.toUpperCase();
  if (normalizedMethod === 'GET' || normalizedMethod === 'HEAD' || normalizedMethod === 'OPTIONS') {
    return true;
  }

  return hasIdempotencyKey(headers);
}

async function executeRequestWithRetry(
  requestFn: () => Promise<AxiosResponse>,
  method: string,
  headers: Record<string, string>,
  verbose: boolean
): Promise<AxiosResponse> {
  const allowRetry = shouldRetryFiveXX(method, headers);
  const maxAttempts = allowRetry ? 3 : 1;
  let attempt = 1;

  while (true) {
    try {
      const response = await requestFn();
      if (response.status >= 500 && response.status <= 599 && attempt < maxAttempts) {
        const backoffMs = 250 * 2 ** (attempt - 1);
        if (verbose) {
          console.error(
            `received HTTP ${response.status}, retrying attempt ${attempt + 1}/${maxAttempts} in ${backoffMs}ms`
          );
        }
        await sleep(backoffMs);
        attempt += 1;
        continue;
      }

      return response;
    } catch (error) {
      if (error instanceof AxiosError && error.response) {
        const response = error.response;
        if (response.status >= 500 && response.status <= 599 && attempt < maxAttempts) {
          const backoffMs = 250 * 2 ** (attempt - 1);
          if (verbose) {
            console.error(
              `received HTTP ${response.status}, retrying attempt ${attempt + 1}/${maxAttempts} in ${backoffMs}ms`
            );
          }
          await sleep(backoffMs);
          attempt += 1;
          continue;
        }

        return response;
      }

      const isNetworkFailure = error instanceof AxiosError && !error.response;
      if (!isNetworkFailure || attempt >= maxAttempts) {
        throw error;
      }

      const backoffMs = 250 * 2 ** (attempt - 1);
      if (verbose) {
        console.error(`network error, retrying attempt ${attempt + 1}/${maxAttempts} in ${backoffMs}ms`);
      }
      await sleep(backoffMs);
      attempt += 1;
    }
  }
}

async function createPaidAxiosClient(
  walletPath: string | undefined,
  token: string | undefined
): Promise<AxiosInstance> {
  void walletPath;
  void token;
  return axios.create();
}

function signCanonicalMessage(message: string, privateKey: string): string {
  const messageHash = createHash('sha256').update(message).digest('hex');
  const signature = signMessageHashRsv({
    messageHash,
    privateKey: createStacksPrivateKey(normalizePrivateKey(privateKey)),
  });

  return Buffer.from(signature.data).toString('base64');
}

function boolResult(value: boolean | undefined): string {
  if (value === undefined) return 'not checked';
  return value ? 'yes' : 'no';
}

function unwrapAxiosError(error: unknown): never {
  if (error instanceof AxiosError) {
    const status = error.response?.status;
    const body = error.response?.data;
    const details = typeof body === 'object' ? JSON.stringify(body) : String(body || error.message);
    throw new Error(status ? `HTTP ${status}: ${details}` : error.message);
  }

  if (error instanceof Error) throw error;
  throw new Error('Unexpected CLI error');
}

const program = new Command();

program
  .name('stxact')
  .description('stxact command-line interface')
  .version('1.0.0');

program
  .command('curl')
  .argument('<url>', 'x402/stxact endpoint URL')
  .option('--method <method>', 'HTTP method', 'GET')
  .option('--header <header...>', 'Header in "Key: Value" format', [])
  .option('--body <body>', 'Raw request body')
  .option('--wallet <path>', 'Path to wallet JSON or plain private key file for x402 auto-pay')
  .option('--token <token>', 'Preferred payment token (sBTC, USDCx, STX)')
  .option('--output <path>', 'Write output JSON to file')
  .option('--verify', 'Attempt receipt verification when response includes receipt header')
  .option('--verbose', 'Print request details')
  .action(async (url: string, options: CurlCommandOptions) => {
    try {
      const method = String(options.method || 'GET').toUpperCase();
      if (!SUPPORTED_CURL_METHODS.has(method)) {
        throw new Error(
          `Unsupported HTTP method "${method}". Supported methods: ${Array.from(SUPPORTED_CURL_METHODS).join(', ')}`
        );
      }

      const headers = parseHeaders(options.header || []);
      const client = await createPaidAxiosClient(options.wallet, options.token);

      if (options.verbose) {
        console.log(`request: ${method} ${url}`);
        if (options.wallet) {
          console.log(`payment: enabled (${getStacksNetwork()}, token=${options.token || 'auto'})`);
        } else {
          console.log('payment: disabled (wallet not provided)');
        }
      }

      let response = await executeRequestWithRetry(
        () =>
          client.request({
            method,
            url,
            headers,
            data: options.body,
          }),
        method,
        headers,
        Boolean(options.verbose)
      );

      if (response.status === 402 && options.wallet) {
        response = await executePaymentRetry(
          client,
          url,
          method,
          headers,
          options.body,
          response,
          options.wallet,
          options.token,
          Boolean(options.verbose)
        );
      }

      if (!options.wallet && response.status === 402) {
        throw new Error('Endpoint requires payment (402). Re-run with --wallet <path> to auto-pay.');
      }

      const receipt = decodeReceiptFromHeader(getHeaderValue(response.headers, 'x-stxact-receipt'));
      const output: Record<string, unknown> = {
        status: response.status,
        response: response.data,
        receipt,
      };

      if (options.verify && receipt) {
        const verify = await axios.post<{ valid: boolean; checks: VerificationChecks }>(
          `${API_BASE_URL}/receipts/verify`,
          { receipt }
        );
        const verificationResult: Record<string, unknown> = {
          signature_valid: verify.data.checks.signature_valid,
          principal_match: verify.data.checks.principal_match,
          payment_txid_confirmed: verify.data.checks.payment_txid_confirmed,
          bns_verified: verify.data.checks.bns_verified,
        };

        if (receipt.delivery_commitment) {
          verificationResult.delivery_hash_match =
            sha256HexFromUnknownPayload(response.data) === receipt.delivery_commitment;
        }

        output.verification = verificationResult;
      }

      const rendered = JSON.stringify(output, null, 2);
      console.log(rendered);

      if (options.output) {
        await fs.writeFile(resolveUserPath(options.output), rendered, 'utf8');
      }
    } catch (error) {
      unwrapAxiosError(error);
    }
  });

function extractReceiptPayload(value: unknown): ReceiptPayload | null {
  if (!value || typeof value !== 'object') {
    return null;
  }

  const directReceipt = value as ReceiptPayload;
  if (typeof directReceipt.receipt_id === 'string') {
    return directReceipt;
  }

  const envelopeReceipt = (value as { receipt?: unknown }).receipt;
  if (envelopeReceipt && typeof envelopeReceipt === 'object') {
    const candidate = envelopeReceipt as ReceiptPayload;
    if (typeof candidate.receipt_id === 'string') {
      return candidate;
    }
  }

  return null;
}

program
  .command('verify-receipt')
  .argument('<receiptFile>', 'path to receipt JSON file')
  .option('--response <path>', 'response artifact file path for delivery hash validation')
  .option('--on-chain', 'validate payment tx on-chain')
  .option('--bns', 'validate BNS ownership')
  .action(async (receiptFile: string, options: VerifyReceiptCommandOptions) => {
    try {
      const receiptFilePayload = await readJsonFile<unknown>(receiptFile);
      const receipt = extractReceiptPayload(receiptFilePayload);
      if (!receipt) {
        throw new Error(
          'Receipt file must contain either a receipt object or a stxact curl output with a top-level "receipt" field'
        );
      }

      const params = new URLSearchParams();
      if (options.onChain) params.set('on_chain', 'true');
      if (options.bns) params.set('bns', 'true');
      const query = params.toString() ? `?${params.toString()}` : '';

      const verifyResponse = await axios.post<{ valid: boolean; checks: VerificationChecks }>(
        `${API_BASE_URL}/receipts/verify${query}`,
        { receipt }
      );

      const checks = verifyResponse.data.checks;
      let deliveryMatch: boolean | undefined;

      if (options.response && receipt.delivery_commitment) {
        const responseBytes = await fs.readFile(resolveUserPath(options.response));
        const responseHash = createHash('sha256').update(responseBytes).digest('hex');
        deliveryMatch = responseHash === receipt.delivery_commitment;
      }

      console.log(`signature valid: ${boolResult(checks.signature_valid)}`);
      console.log(`principal match: ${boolResult(checks.principal_match)}`);
      console.log(`payment confirmed: ${boolResult(checks.payment_txid_confirmed)}`);
      console.log(`bns verified: ${boolResult(checks.bns_verified)}`);
      if (options.response && receipt.delivery_commitment) {
        console.log(`delivery hash match: ${boolResult(deliveryMatch)}`);
      }
      console.log(`overall valid: ${verifyResponse.data.valid ? 'yes' : 'no'}`);
    } catch (error) {
      unwrapAxiosError(error);
    }
  });

const disputeCommand = program.command('dispute').description('dispute operations');

disputeCommand
  .command('create')
  .argument('<receiptId>', 'receipt UUID')
  .argument('<reason>', 'dispute reason')
  .option('--wallet <path>', 'Path to wallet JSON/private key file for buyer signature')
  .option('--evidence <text>', 'plain-text evidence note')
  .option('--expected-hash <hash>', 'expected hash for delivery mismatch')
  .option('--received-hash <hash>', 'received hash for delivery mismatch')
  .action(async (receiptId: string, reason: string, options: DisputeCreateCommandOptions) => {
    try {
      const evidence: Record<string, unknown> = {};
      if (options.evidence) evidence.notes = options.evidence;
      if (options.expectedHash) evidence.expected_hash = options.expectedHash;
      if (options.receivedHash) evidence.received_hash = options.receivedHash;

      let buyerSignature: string | undefined;
      let timestamp: number | undefined;

      if (options.wallet) {
        const privateKey = await loadWalletPrivateKey(options.wallet);
        timestamp = Math.floor(Date.now() / 1000);
        const disputeMessage = ['STXACT-DISPUTE', receiptId, reason, timestamp.toString()].join(':');
        buyerSignature = signCanonicalMessage(disputeMessage, privateKey);
      }

      const response = await axios.post(`${API_BASE_URL}/disputes`, {
        receipt_id: receiptId,
        reason,
        evidence: Object.keys(evidence).length > 0 ? evidence : undefined,
        buyer_signature: buyerSignature,
        timestamp,
      });

      console.log(JSON.stringify(response.data, null, 2));
    } catch (error) {
      unwrapAxiosError(error);
    }
  });

disputeCommand
  .command('status')
  .argument('<disputeId>', 'dispute UUID')
  .action(async (disputeId: string) => {
    try {
      const response = await axios.get(`${API_BASE_URL}/disputes/${disputeId}`);
      console.log(JSON.stringify(response.data, null, 2));
    } catch (error) {
      unwrapAxiosError(error);
    }
  });

disputeCommand
  .command('refund')
  .argument('<disputeId>', 'dispute UUID')
  .argument('<refundAmount>', 'refund amount in microSTX')
  .requiredOption('--wallet <path>', 'Path to seller wallet JSON/private key file for refund signature')
  .action(async (disputeId: string, refundAmount: string, options: DisputeRefundCommandOptions) => {
    try {
      if (!/^[0-9]+$/.test(refundAmount) || refundAmount === '0') {
        throw new Error('Refund amount must be a positive integer in microSTX');
      }

      if (!options.wallet) {
        throw new Error('Seller wallet is required');
      }

      const privateKey = await loadWalletPrivateKey(options.wallet);
      const disputeResponse = await axios.get<{
        dispute_id: string;
        receipt_id?: string;
        buyer_principal?: string;
        seller_principal?: string;
      }>(`${API_BASE_URL}/disputes/${disputeId}`);

      const dispute = disputeResponse.data;
      if (!dispute.receipt_id || !dispute.buyer_principal || !dispute.seller_principal) {
        throw new Error('Dispute is missing receipt_id, buyer_principal, or seller_principal');
      }

      const timestamp = Math.floor(Date.now() / 1000);
      const refundMessage = [
        'STXACT-REFUND',
        dispute.dispute_id,
        dispute.receipt_id,
        refundAmount,
        dispute.buyer_principal,
        dispute.seller_principal,
        timestamp.toString(),
      ].join(':');
      const sellerSignature = signCanonicalMessage(refundMessage, privateKey);

      const response = await axios.post(`${API_BASE_URL}/disputes/refunds`, {
        dispute_id: dispute.dispute_id,
        receipt_id: dispute.receipt_id,
        refund_amount: refundAmount,
        buyer_principal: dispute.buyer_principal,
        timestamp,
        seller_signature: sellerSignature,
      });

      console.log(JSON.stringify(response.data, null, 2));
    } catch (error) {
      unwrapAxiosError(error);
    }
  });

program
  .command('list-services')
  .option('--min-rep <score>', 'minimum reputation score')
  .option('--category <category>', 'category filter')
  .option('--token <token>', 'supported token filter')
  .option('--limit <limit>', 'result limit', '50')
  .option('--format <format>', 'table, json, or csv output', 'table')
  .action(async (options: ListServicesCommandOptions) => {
    try {
      const format = (options.format || 'table').toLowerCase();
      const params = new URLSearchParams();
      if (options.minRep) params.set('min_reputation', String(options.minRep));
      if (options.category) params.set('category', String(options.category));
      if (options.token) params.set('supported_token', String(options.token));
      params.set('limit', String(options.limit || 50));

      const response = await axios.get<{
        services: Array<{
          principal: string;
          bns_name?: string | null;
          endpoint_url: string;
          reputation?: { score: number; success_rate: number };
          supported_tokens?: Array<{ symbol: string }>;
        }>;
      }>(`${API_BASE_URL}/directory/services?${params.toString()}`);

      if (format === 'json') {
        console.log(JSON.stringify(response.data, null, 2));
        return;
      }

      if (format === 'csv') {
        const escapeCsv = (value: string): string => {
          if (value.includes('"') || value.includes(',') || value.includes('\n')) {
            return `"${value.replace(/"/g, '""')}"`;
          }
          return value;
        };

        const lines = ['service,principal,reputation,success_rate,tokens,endpoint'];
        response.data.services.forEach((service) => {
          const serviceName = service.bns_name || service.principal.slice(0, 14);
          const reputation = String(service.reputation?.score || 0);
          const successRate = `${((service.reputation?.success_rate || 0) * 100).toFixed(2)}%`;
          const tokens = (service.supported_tokens || []).map((token) => token.symbol).join('|');
          lines.push(
            [
              serviceName,
              service.principal,
              reputation,
              successRate,
              tokens,
              service.endpoint_url,
            ]
              .map((value) => escapeCsv(value))
              .join(',')
          );
        });
        console.log(lines.join('\n'));
        return;
      }

      if (format !== 'table') {
        throw new Error(`Unsupported format "${options.format}". Use table, json, or csv.`);
      }

      const table = new Table({
        head: ['Service', 'Reputation', 'Success Rate', 'Tokens', 'Endpoint'],
      });

      response.data.services.forEach((service) => {
        table.push([
          service.bns_name || service.principal.slice(0, 14),
          String(service.reputation?.score || 0),
          `${((service.reputation?.success_rate || 0) * 100).toFixed(2)}%`,
          (service.supported_tokens || []).map((token) => token.symbol).join(', '),
          service.endpoint_url,
        ]);
      });

      console.log(table.toString());
      console.log(`total services: ${response.data.services.length}`);
    } catch (error) {
      unwrapAxiosError(error);
    }
  });

program.parseAsync(process.argv).catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
export const CLI_THEME = 'professional';
