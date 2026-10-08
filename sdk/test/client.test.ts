import { afterEach, describe, expect, it } from "vitest";
import { createAgentPay } from "../src/x402/client.js";
import { MerchantRegistry } from "../src/policy/registry.js";
import { PaymentBlockedError, PaymentDeniedError } from "../src/guard/controls.js";
import { verifyChain } from "../src/guard/audit.js";
import { startMockServer, type MockServer } from "../examples/mock-x402-server.js";
import { ATTACKER, MERCHANT_PAYTO, NETWORK, payer, policy } from "./fixtures.js";

let server: MockServer | undefined;
afterEach(async () => server?.close());

const safeSession = { readsUntrustedInput: true, accessesSensitiveData: false, canPay: true };

async function client(routes: Parameters<typeof startMockServer>[0], extra: Partial<Parameters<typeof createAgentPay>[0]> = {}) {
  server = await startMockServer(routes);
  const registry = new MerchantRegistry([
    { origin: server.url, payTo: MERCHANT_PAYTO, network: NETWORK, maxPerTx: 1_000_000n, pricePin: 10_000n },
  ]);
  const pay = createAgentPay({ registry, policy, payer: () => payer, session: safeSession, ...extra });
  const plan = pay.commitPlan([{ origin: server.url, maxSpend: 100_000n }], 60_000);
  return { pay, plan, url: server.url };
}

describe("x402 client", () => {
  it("pays a real v1 402 end-to-end", async () => {
    // 1. Setup the real Neynar JSON shape we captured
    const neynarV1Body = {
      x402Version: 1,
      error: "X-PAYMENT header or API key required",
      accepts: [{
        scheme: "exact",
        network: "base",
        maxAmountRequired: "10000",
        resource: "http://127.0.0.1/farcaster/user/bulk",
        payTo: MERCHANT_PAYTO, // using fixture address for tests
        maxTimeoutSeconds: 60,
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      }]
    };

    // 2. Mock fetch to return the JSON body instead of a PAYMENT-REQUIRED header
    let fetchCount = 0;
    const fetchMock = async (input: RequestInfo | URL, init?: RequestInit) => {
      fetchCount++;
      const headers = new Headers(init?.headers);
      
      // On the second request, verify the agent sent the v1 payload format in the correct header
      if (headers.has("X-PAYMENT")) {
        const payload = JSON.parse(Buffer.from(headers.get("X-PAYMENT") as string, "base64").toString("utf-8"));
        expect(payload.x402Version).toBe(1);
        expect(payload.network).toBe("base"); // must be 'base', not 'eip155:8453' in the payload
        expect(payload.payload.signature).toBeDefined();
        return new Response(null, { status: 200, headers: { "X-PAYMENT-RESPONSE": JSON.stringify({ success: true, network: "eip155:8453", transaction: "0x..." }) } });
      }

      // First request returns the 402 with the JSON body
      return new Response(JSON.stringify(neynarV1Body), { status: 402, headers: { "Content-Type": "application/json" } });
    };

    // 3. Initialize the agent using a local IP to bypass static outbound network checks
    const mockOrigin = "http://127.0.0.1";
    const registry = new MerchantRegistry([{ origin: mockOrigin, payTo: MERCHANT_PAYTO, network: "eip155:8453", maxPerTx: 100_000n, pricePin: 10_000n }]);
    const v1Policy = { ...policy, acceptV1: true };
    const pay = createAgentPay({ registry, policy: v1Policy, payer: () => payer, session: safeSession, fetch: fetchMock as typeof fetch });
    const plan = pay.commitPlan([{ origin: mockOrigin, maxSpend: 100_000n }], 60_000);
    
    const res = await pay.fetch(`${mockOrigin}/v2/farcaster/user/bulk?fids=3`, {}, { plan });
    
    expect(res.status).toBe(200);
    expect(fetchCount).toBe(2);
  });

  it("refuses hostile v1 402s with zero signatures", async () => {
    // 1. Setup a hostile payload (amount higher than maxPerTx)
    const hostileBody = {
      x402Version: 1,
      accepts: [{
        scheme: "exact",
        network: "base",
        maxAmountRequired: "9999999999999999", // Hostile: Way too high
        payTo: MERCHANT_PAYTO,
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      }]
    };

    const fetchMock = async () => new Response(JSON.stringify(hostileBody), { status: 402, headers: { "Content-Type": "application/json" } });

    const mockOrigin = "http://127.0.0.1";
    const registry = new MerchantRegistry([{ origin: mockOrigin, payTo: MERCHANT_PAYTO, network: "eip155:8453", maxPerTx: 10_000n }]);
    const pay = createAgentPay({ registry, policy: { ...policy, acceptV1: true }, payer: () => payer, session: safeSession, fetch: fetchMock as typeof fetch });
    const plan = pay.commitPlan([{ origin: mockOrigin, maxSpend: 100_000n }], 60_000);
    
    // Ensure the guard blocks it and NO signatures were generated
    await expect(pay.fetch(`${mockOrigin}/x`, {}, { plan })).rejects.toThrow();
    expect(pay.audit.entries.some(e => e.event.type === "payment.signed")).toBe(false);
  });
  
  it("pays an honest merchant and records a verifiable audit chain", async () => {
    const { pay, plan, url } = await client({ "/data": { price: 10_000n, payTo: MERCHANT_PAYTO } });
    const res = await pay.fetch(`${url}/data`, {}, { plan });
    expect(res.status).toBe(200);
    expect(res.payment?.settlement.success).toBe(true);
    expect(server!.received).toHaveLength(1);
    expect(server!.received[0]!.payload.authorization.to).toBe(MERCHANT_PAYTO);
    expect(plan.remaining(url)).toBe(90_000n);
    expect(verifyChain(pay.audit.entries)).toBe(-1);
    expect(pay.audit.entries.map((e) => e.event.type)).toEqual(["plan.sealed", "payment.signed", "payment.settled"]);
  });

  it("never signs when the server swaps the payee", async () => {
    const { pay, plan, url } = await client({
      "/data": { price: 10_000n, payTo: MERCHANT_PAYTO, tamper: (r) => ({ ...r, payTo: ATTACKER }) },
    });
    await expect(pay.fetch(`${url}/data`, {}, { plan })).rejects.toBeInstanceOf(PaymentDeniedError);
    expect(server!.received).toHaveLength(0);
  });

  it("never signs when the server raises the price", async () => {
    const { pay, plan, url } = await client({ "/data": { price: 900_000n, payTo: MERCHANT_PAYTO } });
    await expect(pay.fetch(`${url}/data`, {}, { plan })).rejects.toThrow(/pinned price/);
    expect(server!.received).toHaveLength(0);
  });

  it("retries a failed settlement only with the same signed authorization, then gives up", async () => {
    const { pay, plan, url } = await client(
      {
        // The server under-quotes, then the facilitator rejects the payment as insufficient, every time.
        "/data": { price: 10_000n, payTo: MERCHANT_PAYTO, tamper: (r) => ({ ...r, amount: "9000" }) },
      },
      { settleRetryDelayMs: 1 },
    );
    await expect(pay.fetch(`${url}/data`, {}, { plan })).rejects.toBeInstanceOf(PaymentBlockedError);
    // One authorization, sent four times (initial + 3 retries): its EIP-3009 nonce can execute at most once.
    expect(server!.received).toHaveLength(4);
    const nonces = new Set(server!.received.map((r) => r.payload.authorization.nonce));
    const sigs = new Set(server!.received.map((r) => r.payload.signature));
    expect(nonces.size).toBe(1);
    expect(sigs.size).toBe(1);
    expect(plan.remaining(url)).toBe(91_000n); // the 9,000 under-quote, counted once
    expect(pay.audit.entries.filter((e) => e.event.type === "payment.signed")).toHaveLength(1);
    expect(pay.audit.entries.filter((e) => e.event.type === "payment.retry")).toHaveLength(3);
  });

  it("recovers from a transient settlement failure by resending the same authorization", async () => {
    let first = true;
    let firstHeader = "";
    const flaky = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const sig = new Headers(init?.headers).get("PAYMENT-SIGNATURE");
      if (sig && first) {
        first = false;
        firstHeader = sig;
        return new Response(null, { status: 402 }); // e.g. the facilitator's node had not seen the top-up yet
      }
      if (sig) expect(sig).toBe(firstHeader);
      return fetch(input, init);
    }) as typeof fetch;
    const { pay, plan, url } = await client({ "/data": { price: 10_000n, payTo: MERCHANT_PAYTO } }, { fetch: flaky, settleRetryDelayMs: 1 });
    const res = await pay.fetch(`${url}/data`, {}, { plan });
    expect(res.status).toBe(200);
    expect(res.payment?.settlement.success).toBe(true);
    expect(server!.received).toHaveLength(1);
    expect(plan.remaining(url)).toBe(90_000n);
  });

  it("requires a human when the session breaks the Rule of Two, and respects a refusal", async () => {
    let asked = 0;
    const { pay, plan, url } = await client(
      { "/data": { price: 10_000n, payTo: MERCHANT_PAYTO } },
      {
        session: { readsUntrustedInput: true, accessesSensitiveData: true, canPay: true },
        approve: async () => {
          asked++;
          return false;
        },
      },
    );
    await expect(pay.fetch(`${url}/data`, {}, { plan })).rejects.toThrow(/human approval refused/);
    expect(asked).toBe(1);
    expect(server!.received).toHaveLength(0);
  });

  it("refuses to pay a sanctioned payee even if the owner registered it", async () => {
    const { staticListScreen } = await import("../src/policy/sanctions.js");
    const { pay, plan, url } = await client(
      { "/data": { price: 10_000n, payTo: MERCHANT_PAYTO } },
      { screen: staticListScreen([MERCHANT_PAYTO]) },
    );
    await expect(pay.fetch(`${url}/data`, {}, { plan })).rejects.toThrow(/sanctions screening/);
    expect(server!.received).toHaveLength(0);
  });

  it("an unreachable sanctions oracle blocks payments (fail closed)", async () => {
    const { oracleScreen } = await import("../src/policy/sanctions.js");
    const { createPublicClient, http } = await import("viem");
    const dead = createPublicClient({ transport: http("http://127.0.0.1:1") });
    expect(await oracleScreen(dead, "0x40C57923924B5c5c5455c48D93317139ADDaC8fb")(MERCHANT_PAYTO)).toBe(true);
  });

  it("stops everything after the kill switch", async () => {
    const { pay, plan, url } = await client({ "/data": { price: 10_000n, payTo: MERCHANT_PAYTO } });
    pay.kill("anomaly");
    await expect(pay.fetch(`${url}/data`, {}, { plan })).rejects.toThrow(/kill switch/);
  });

  it("rate-limits bursts", async () => {
    const { pay, plan, url } = await client(
      { "/data": { price: 10_000n, payTo: MERCHANT_PAYTO } },
      { rateLimit: { max: 2, windowMs: 60_000 } },
    );
    await pay.fetch(`${url}/data`, {}, { plan });
    await pay.fetch(`${url}/data`, {}, { plan });
    await expect(pay.fetch(`${url}/data`, {}, { plan })).rejects.toThrow(/rate limit/);
    expect(server!.received).toHaveLength(2);
  });

  it("refuses a 402 that arrives through a cross-origin redirect", async () => {
    const registry = new MerchantRegistry([{ origin: "https://shop.example", payTo: MERCHANT_PAYTO, network: NETWORK, maxPerTx: 1n }]);
    const redirected = async () => {
      const r = new Response(null, { status: 402, headers: { "PAYMENT-REQUIRED": "e30=" } });
      Object.defineProperty(r, "redirected", { value: true });
      Object.defineProperty(r, "url", { value: "https://evil.example/pay" });
      return r;
    };
    const pay = createAgentPay({ registry, policy, payer: () => payer, session: safeSession, fetch: redirected as typeof fetch });
    const plan = pay.commitPlan([{ origin: "https://shop.example", maxSpend: 1n }], 60_000);
    await expect(pay.fetch("https://shop.example/x", {}, { plan })).rejects.toThrow(/redirect/);
  });

  it("rejects malformed or oversized 402 headers", async () => {
    const registry = new MerchantRegistry([{ origin: "https://shop.example", payTo: MERCHANT_PAYTO, network: NETWORK, maxPerTx: 1n }]);
    const fake = async () => new Response(null, { status: 402, headers: { "PAYMENT-REQUIRED": "A".repeat(20_000) } });
    const pay = createAgentPay({ registry, policy, payer: () => payer, session: safeSession, fetch: fake as typeof fetch });
    const plan = pay.commitPlan([{ origin: "https://shop.example", maxSpend: 1n }], 60_000);
    await expect(pay.fetch("https://shop.example/x", {}, { plan })).rejects.toThrow(/too large/);
  });
});
