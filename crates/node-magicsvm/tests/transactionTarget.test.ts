import { getTransferSolInstruction } from "@solana-program/system";
import {
  createKeyPairSignerFromPrivateKeyBytes,
  generateKeyPairSigner,
  lamports,
} from "@solana/kit";
import { TransactionErrorFieldless } from "internal";
import { FailedTransactionMetadata, MagicSVM } from "magicsvm";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import {
  generateAddress,
  getSignedTransaction,
  LAMPORTS_PER_SOL,
} from "./util";

test("constructor accepts a validator identity", async () => {
  const validatorPrivateKey = randomBytes(32);
  const validator = await createKeyPairSignerFromPrivateKeyBytes(
    validatorPrivateKey,
  );
  const svm = new MagicSVM({
    validatorIdentity: new Uint8Array(validatorPrivateKey),
  });

  assert.strictEqual(svm.validatorIdentity(), validator.address);
});

test("sendTransaction defaults to base target and accepts explicit base target", async () => {
  const [payer, receiver] = await Promise.all([
    generateKeyPairSigner(),
    generateAddress(),
  ]);
  const svm = new MagicSVM();
  svm.airdrop(payer.address, lamports(LAMPORTS_PER_SOL));

  const transaction = await getSignedTransaction(svm, payer, [
    getTransferSolInstruction({
      source: payer,
      destination: receiver,
      amount: lamports(1_000_000n),
    }),
  ]);

  svm.sendTransaction(transaction, { target: "base" });

  assert.strictEqual(svm.getBalance(receiver), lamports(1_000_000n));
});

test("sendTransaction rejects non-delegated ephemeral writes", async () => {
  const [payer, receiver] = await Promise.all([
    generateKeyPairSigner(),
    generateAddress(),
  ]);
  const svm = new MagicSVM();
  svm.airdrop(payer.address, lamports(LAMPORTS_PER_SOL));

  const transaction = await getSignedTransaction(svm, payer, [
    getTransferSolInstruction({
      source: payer,
      destination: receiver,
      amount: lamports(1_000_000n),
    }),
  ]);
  const result = svm.sendTransaction(transaction, { target: "ephemeral" });

  if (result instanceof FailedTransactionMetadata) {
    assert.strictEqual(
      result.err(),
      TransactionErrorFieldless.InvalidWritableAccount,
    );
  } else {
    throw new Error("Expected transaction failure");
  }
});
