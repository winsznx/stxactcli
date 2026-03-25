import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

const execFileAsync = promisify(execFile);

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      const address = server.address();
      resolve(address);
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function readJsonBody(req) {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(Buffer.from(chunk));
  }

  const body = Buffer.concat(chunks).toString('utf8');
  return body ? JSON.parse(body) : {};
}

function sendJson(res, statusCode, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    ...headers,
  });
  res.end(body);
}

test('CLI commands work end-to-end against local x402 and API harnesses', async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'stxact-cli-e2e-'));
  const cliEntry = path.resolve('dist/index.js');
  const walletPath = path.join(tempDir, 'wallet.json');
  const sellerWalletPath = path.join(tempDir, 'seller-wallet.json');
  const curlOutputPath = path.join(tempDir, 'curl-output.json');
  const responseArtifactPath = path.join(tempDir, 'premium-response.json');
  const disputeId = '5ec77c0f-845d-41b9-a33b-a50f16449fc0';
  const receiptId = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
  const sellerPrincipal = 'ST3JEA5ZE0YC4MG00SNXG1JYBAHCH3HA1RKF4S49Y';
  const buyerPrincipal = 'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG';
  const refundTxid = '0xrefund-mock-payment';
  const premiumResponse = {
    dataset: 'institutional-btc-yield',
    window: '2026-Q1',
    confidence: 0.97,
  };
  const premiumResponseBody = JSON.stringify(premiumResponse);
  const deliveryCommitment = createHash('sha256').update(premiumResponseBody).digest('hex');

  const state = {
    paidRequestCount: 0,
    verifyCalls: [],
    disputes: new Map(),
  };

  await writeFile(
    walletPath,
    JSON.stringify({
      privateKey: '6e809f10f8f2fd59837f5734478f729dff73ffb522d4f19f280f9cd8ab0b47c2',
    }),
    'utf8'
  );
  await writeFile(
    sellerWalletPath,
    JSON.stringify({
      privateKey: '1111111111111111111111111111111111111111111111111111111111111111',
    }),
    'utf8'
  );
  await writeFile(responseArtifactPath, premiumResponseBody, 'utf8');

  const stacksServer = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/v2/fees/transfer') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('1');
      return;
    }

    if (req.method === 'POST' && req.url === '/v2/fees/transaction') {
      sendJson(res, 200, {
        estimations: [
          { fee: 180, fee_rate: 1 },
          { fee: 200, fee_rate: 1 },
          { fee: 220, fee_rate: 1 },
        ],
      });
      return;
    }

    if (req.method === 'GET' && req.url && req.url.includes('/extended/v1/address/')) {
      sendJson(res, 200, { possible_next_nonce: 0 });
      return;
    }

    sendJson(res, 404, { error: 'not_found' });
  });

  const apiServer = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');

    if (req.method === 'GET' && url.pathname === '/premium-data') {
      const paymentSignature = req.headers['payment-signature'];

      if (!paymentSignature || Array.isArray(paymentSignature)) {
        const paymentRequired = {
          x402Version: 2,
          resource: {
            url: 'http://127.0.0.1/premium-data',
            description: 'Premium BTC treasury data',
            mimeType: 'application/json',
          },
          accepts: [
            {
              scheme: 'exact',
              network: 'stacks:2147483648',
              asset: 'STX',
              amount: '100000',
              payTo: sellerPrincipal,
            },
          ],
        };

        const headerValue = Buffer.from(JSON.stringify(paymentRequired)).toString('base64');
        sendJson(res, 402, paymentRequired, { 'payment-required': headerValue });
        return;
      }

      const decodedPayment = JSON.parse(
        Buffer.from(paymentSignature, 'base64').toString('utf8')
      );

      state.paidRequestCount += 1;
      assert.equal(decodedPayment.x402Version, 2);
      assert.equal(decodedPayment.accepted.asset, 'STX');
      assert.ok(typeof decodedPayment.payload.transaction === 'string');
      assert.ok(decodedPayment.payload.transaction.length > 0);

      const receipt = {
        receipt_id: receiptId,
        request_hash: 'test-request-hash',
        payment_txid: '0xcli-mock-payment',
        seller_principal: sellerPrincipal,
        buyer_principal: buyerPrincipal,
        delivery_commitment: deliveryCommitment,
        timestamp: 1_772_366_400,
        signature: 'mock-signature',
      };

      sendJson(
        res,
        200,
        premiumResponse,
        {
          'x-stxact-receipt': Buffer.from(JSON.stringify(receipt)).toString('base64'),
        }
      );
      return;
    }

    if (req.method === 'POST' && url.pathname === '/receipts/verify') {
      const payload = await readJsonBody(req);
      state.verifyCalls.push({
        on_chain: url.searchParams.get('on_chain'),
        bns: url.searchParams.get('bns'),
        receipt_id: payload?.receipt?.receipt_id,
      });

      sendJson(res, 200, {
        valid: true,
        checks: {
          signature_valid: true,
          principal_match: true,
          payment_txid_confirmed: url.searchParams.get('on_chain') === 'true',
          bns_verified: url.searchParams.get('bns') === 'true',
        },
      });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/disputes') {
      const payload = await readJsonBody(req);
      assert.equal(payload.receipt_id, receiptId);
      assert.equal(payload.reason, 'no_response');
      assert.ok(typeof payload.buyer_signature === 'string');
      assert.ok(typeof payload.timestamp === 'number');

      const dispute = {
        dispute_id: disputeId,
        receipt_id: payload.receipt_id,
        buyer_principal: buyerPrincipal,
        seller_principal: sellerPrincipal,
        reason: payload.reason,
        status: 'open',
        created_at: 1_772_366_500,
      };
      state.disputes.set(disputeId, dispute);
      sendJson(res, 201, dispute);
      return;
    }

    if (req.method === 'GET' && url.pathname === `/disputes/${disputeId}`) {
      sendJson(res, 200, state.disputes.get(disputeId));
      return;
    }

    if (req.method === 'POST' && url.pathname === '/disputes/refunds') {
      const payload = await readJsonBody(req);
      assert.equal(payload.dispute_id, disputeId);
      assert.equal(payload.receipt_id, receiptId);
      assert.equal(payload.refund_amount, '150000');
      assert.equal(payload.buyer_principal, buyerPrincipal);
      assert.ok(typeof payload.timestamp === 'number');
      assert.ok(typeof payload.seller_signature === 'string');

      const updatedDispute = {
        ...state.disputes.get(disputeId),
        status: 'refunded',
        refund_amount: payload.refund_amount,
        refund_txid: refundTxid,
        resolved_at: 1_772_366_600,
      };

      state.disputes.set(disputeId, updatedDispute);
      sendJson(res, 200, {
        status: 'refunded',
        dispute_id: disputeId,
        refund_txid: refundTxid,
        refund_amount: payload.refund_amount,
        buyer_principal: buyerPrincipal,
        seller_principal: sellerPrincipal,
      });
      return;
    }

    sendJson(res, 404, { error: 'not_found', path: url.pathname });
  });

  let stacksAddress;
  let apiAddress;

  try {
    stacksAddress = await listen(stacksServer);
    apiAddress = await listen(apiServer);

    const sharedEnv = {
      ...process.env,
      STXACT_API_URL: `http://127.0.0.1:${apiAddress.port}`,
      STXACT_STACKS_API_URL: `http://127.0.0.1:${stacksAddress.port}`,
      STXACT_STACKS_NETWORK: 'testnet',
    };

    const curlResult = await execFileAsync(
      process.execPath,
      [
        cliEntry,
        'curl',
        `http://127.0.0.1:${apiAddress.port}/premium-data`,
        '--wallet',
        walletPath,
        '--verify',
        '--output',
        curlOutputPath,
      ],
      { cwd: path.resolve('.'), env: sharedEnv }
    );

    const curlOutput = JSON.parse(curlResult.stdout.trim());
    assert.equal(curlOutput.status, 200);
    assert.equal(curlOutput.response.dataset, premiumResponse.dataset);
    assert.equal(curlOutput.receipt.receipt_id, receiptId);
    assert.equal(curlOutput.verification.signature_valid, true);
    assert.equal(curlOutput.verification.principal_match, true);
    assert.equal(curlOutput.verification.delivery_hash_match, true);
    assert.equal(state.paidRequestCount, 1);

    const savedCurlOutput = JSON.parse(await readFile(curlOutputPath, 'utf8'));
    assert.equal(savedCurlOutput.receipt.receipt_id, receiptId);

    const verifyResult = await execFileAsync(
      process.execPath,
      [
        cliEntry,
        'verify-receipt',
        curlOutputPath,
        '--response',
        responseArtifactPath,
        '--on-chain',
      ],
      { cwd: path.resolve('.'), env: sharedEnv }
    );

    assert.match(verifyResult.stdout, /signature valid: yes/);
    assert.match(verifyResult.stdout, /principal match: yes/);
    assert.match(verifyResult.stdout, /payment confirmed: yes/);
    assert.match(verifyResult.stdout, /delivery hash match: yes/);
    assert.match(verifyResult.stdout, /overall valid: yes/);

    const disputeCreateResult = await execFileAsync(
      process.execPath,
      [
        cliEntry,
        'dispute',
        'create',
        receiptId,
        'no_response',
        '--wallet',
        walletPath,
        '--evidence',
        'Seller did not deliver within SLA',
      ],
      { cwd: path.resolve('.'), env: sharedEnv }
    );

    const createdDispute = JSON.parse(disputeCreateResult.stdout.trim());
    assert.equal(createdDispute.dispute_id, disputeId);
    assert.equal(createdDispute.status, 'open');

    const disputeStatusResult = await execFileAsync(
      process.execPath,
      [cliEntry, 'dispute', 'status', disputeId],
      { cwd: path.resolve('.'), env: sharedEnv }
    );

    const disputeStatus = JSON.parse(disputeStatusResult.stdout.trim());
    assert.equal(disputeStatus.dispute_id, disputeId);
    assert.equal(disputeStatus.status, 'open');

    const refundResult = await execFileAsync(
      process.execPath,
      [
        cliEntry,
        'dispute',
        'refund',
        disputeId,
        '150000',
        '--wallet',
        sellerWalletPath,
      ],
      { cwd: path.resolve('.'), env: sharedEnv }
    );

    const refundedDispute = JSON.parse(refundResult.stdout.trim());
    assert.equal(refundedDispute.dispute_id, disputeId);
    assert.equal(refundedDispute.status, 'refunded');
    assert.equal(refundedDispute.refund_txid, refundTxid);

    const refundedStatusResult = await execFileAsync(
      process.execPath,
      [cliEntry, 'dispute', 'status', disputeId],
      { cwd: path.resolve('.'), env: sharedEnv }
    );

    const refundedStatus = JSON.parse(refundedStatusResult.stdout.trim());
    assert.equal(refundedStatus.dispute_id, disputeId);
    assert.equal(refundedStatus.status, 'refunded');
    assert.equal(refundedStatus.refund_txid, refundTxid);

    assert.deepEqual(
      state.verifyCalls.map((call) => ({
        on_chain: call.on_chain,
        receipt_id: call.receipt_id,
      })),
      [
        { on_chain: null, receipt_id: receiptId },
        { on_chain: 'true', receipt_id: receiptId },
      ]
    );
  } finally {
    await Promise.allSettled([close(apiServer), close(stacksServer)]);
    await rm(tempDir, { recursive: true, force: true });
  }
});
