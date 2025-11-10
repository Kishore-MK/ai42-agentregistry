import * as anchor from "@coral-xyz/anchor";
import {
  SystemProgram,
  PublicKey,
  Keypair,
} from "@solana/web3.js";
import { BN } from "bn.js";
import fs from "fs";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { idl } from "./idl"; // Your agent registry IDL

// Load wallet
const secretKeyString = fs.readFileSync("wallet1.json", "utf8");
const secretKey = Uint8Array.from(JSON.parse(secretKeyString));
const keypair = Keypair.fromSecretKey(secretKey);
const user = new anchor.Wallet(keypair);

export const connection = new anchor.web3.Connection(
  "http://127.0.0.1:8899",
  "confirmed"
);

const provider = new anchor.AnchorProvider(connection, user, {
  preflightCommitment: "confirmed",
});

anchor.setProvider(provider);
export const program = new anchor.Program(idl, provider);

// Helper: Generate random agent ID
function generateAgentId(): number[] {
  return Array.from(nacl.randomBytes(32));
}

// Helper: Generate random intent hash
function generateIntentHash(): number[] {
  return Array.from(nacl.randomBytes(32));
}

// 1. Initialize Registry
async function initializeRegistry() {
  const [registryPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("registry")],
    program.programId
  );

  const tx = await program.methods
    .initialize()
    .accounts({
      registry: registryPDA,
      authority: user.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .signers([user.payer])
    .rpc();

  console.log("✅ Registry initialized:", tx);
  return registryPDA;
}

// 2. Register Agent
async function registerAgent(agentId: number[]) {
  const [registryPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("registry")],
    program.programId
  );

  const [agentPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), Buffer.from(agentId)],
    program.programId
  );

  const publicKeyJwk = JSON.stringify({
    kty: "OKP",
    crv: "Ed25519",
    x: bs58.encode(user.publicKey.toBytes()),
  });

  const metadataUri = "https://example.com/agent-metadata.json";

  const tx = await program.methods
    .registerAgent(agentId, publicKeyJwk, metadataUri)
    .accounts({
      agent: agentPDA,
      registry: registryPDA,
      owner: user.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .signers([user.payer])
    .rpc();

  console.log("✅ Agent registered:", tx);
  console.log("Agent PDA:", agentPDA.toBase58());
  return agentPDA;
}

// 3. Update Agent Status
async function updateAgentStatus(agentPDA: PublicKey, isActive: boolean) {
  const [registryPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("registry")],
    program.programId
  );

  const tx = await program.methods
    .updateAgentStatus(isActive)
    .accounts({
      agent: agentPDA,
      registry: registryPDA,
      signer: user.publicKey,
    })
    .signers([user.payer])
    .rpc();

  console.log(`✅ Agent status updated to ${isActive}:`, tx);
}

// 4. Record Intent
async function recordIntent(
  agentPDA: PublicKey,
  intentHash: number[],
  maxAmount: number,
  merchant: string,
  expiresInSeconds: number
) {
  const currentTime = Math.floor(Date.now() / 1000);
  const expiresAt = currentTime + expiresInSeconds;

  const [intentPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("intent"), Buffer.from(intentHash)],
    program.programId
  );

  // Create user signature (signing the intent hash)
  const userSignature = nacl.sign.detached(
    Buffer.from(intentHash),
    user.payer.secretKey
  );

  const tx = await program.methods
    .recordIntent(
      intentHash,
      Buffer.from(userSignature),
      new BN(maxAmount),
      merchant,
      new BN(expiresAt)
    )
    .accounts({
      intent: intentPDA,
      agent: agentPDA,
      user: user.publicKey,
      payer: user.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .signers([user.payer])
    .rpc();

  console.log("✅ Intent recorded:", tx);
  console.log("Intent PDA:", intentPDA.toBase58());
  return { intentPDA, expiresAt };
}

// 5. Verify Intent
async function verifyIntent(intentPDA: PublicKey) {
  const result = await program.methods
    .verifyIntent()
    .accounts({
      intent: intentPDA,
    })
    .view();

  console.log("✅ Intent verification result:", result);
  return result;
}

// 6. Execute Intent (with real Ed25519 signature)
async function executeIntent(intentPDA: PublicKey, agentPDA: PublicKey) {
    const merchantKeypair = Keypair.generate();
    
    const orderId = `ORDER-${Date.now()}`;
    const amount = 50000000;
    const timestamp = Math.floor(Date.now() / 1000);
  
    const message = `${orderId}${amount}${timestamp}`;
    const messageBytes = new TextEncoder().encode(message);
  
    const signature = nacl.sign.detached(messageBytes, merchantKeypair.secretKey);
  
    // Create Ed25519 verify instruction
    const ed25519Instruction = anchor.web3.Ed25519Program.createInstructionWithPublicKey({
      publicKey: merchantKeypair.publicKey.toBytes(),
      message: messageBytes,
      signature: signature,
    });
  
    const merchantProof = {
      orderId: orderId,
      amount: new BN(amount),
      timestamp: new BN(timestamp),
      merchantSignature: Buffer.from(signature),
      merchantPublicKey: merchantKeypair.publicKey.toBytes(),
    };
  
    const tx = await program.methods
      .executeIntent(merchantProof)
      .accounts({
        intent: intentPDA,
        agent: agentPDA,
        executor: user.publicKey,
        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .preInstructions([
        ed25519Instruction,  // Add Ed25519 instruction FIRST
        anchor.web3.ComputeBudgetProgram.setComputeUnitLimit({ 
          units: 200_000
        })
      ])
      .signers([user.payer])
      .rpc();
  
    console.log("✅ Intent executed:", tx);
  }

// 7. Revoke Intent
async function revokeIntent(intentPDA: PublicKey) {
  const tx = await program.methods
    .revokeIntent()
    .accounts({
      intent: intentPDA,
      user: user.publicKey,
    })
    .signers([user.payer])
    .rpc();

  console.log("✅ Intent revoked:", tx);
}

// 8. Update Reputation
async function updateReputation(
  agentPDA: PublicKey,
  scoreDelta: number,
  reason: string
) {
  const [registryPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("registry")],
    program.programId
  );

  const tx = await program.methods
    .updateReputation(new BN(scoreDelta), reason)
    .accounts({
      agent: agentPDA,
      registry: registryPDA,
      authority: user.publicKey,
    })
    .signers([user.payer])
    .rpc();

  console.log(`✅ Reputation updated by ${scoreDelta}:`, tx);
}

// 9. Get Agent Score
async function getAgentScore(agentPDA: PublicKey) {
  const score = await program.methods
    .getAgentScore()
    .accounts({
      agent: agentPDA,
    })
    .view();

  console.log("✅ Agent score:", score.toString());
  return score;
}

// Main test runner
async function runAgentRegistryTests() {
  try {
    console.log("🚀 Starting Agent Registry Tests...\n");

    // // 1. Initialize
    // console.log("1️⃣ Initializing registry...");
    // await initializeRegistry();
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // // 2. Register Agent
    // console.log("\n2️⃣ Registering agent...");
    // const agentId = generateAgentId();
    // const agentPDA = await registerAgent(agentId); 
    // console.log(agentPDA);
    
    const agentPDA= "2aC1gLPKVLcgvEvfG2DdTngQGQTjXopBpCM7z3xSMYDw"
    // // 3. Get initial score
    // console.log("\n3️⃣ Getting initial agent score...");
    // await getAgentScore(agentPDA); 

    // // // 4. Record Intent
    // console.log("\n4️⃣ Recording intent...");
    // const intentHash = generateIntentHash();
    // const { intentPDA, expiresAt } = await recordIntent(
    //   agentPDA,
    //   intentHash,
    //   100000000, // 0.1 SOL max
    //   "Amazon",
    //   3600 // Expires in 1 hour
    // );
    // console.log(intentPDA,expiresAt);
    
    const intentPDA = "Akv5pDqi1R4UJxwg2Vx3rfz2tWhbMogDF1VoQQsdbKk3"
    // 5. Verify Intent
    console.log("\n5️⃣ Verifying intent...");
    await verifyIntent(intentPDA);
    await new Promise(resolve => setTimeout(resolve, 1000));

    // 6. Execute Intent
    // console.log("\n6️⃣ Executing intent with real Ed25519 signature...");
    // await executeIntent(intentPDA, agentPDA);
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // // 7. Get updated score
    // console.log("\n7️⃣ Getting updated agent score...");
    // await getAgentScore(agentPDA);
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // // 8. Test another intent for revocation
    // console.log("\n8️⃣ Recording another intent for revocation test...");
    // const intentHash2 = generateIntentHash();
    // const { intentPDA: intentPDA2 } = await recordIntent(
    //   agentPDA,
    //   intentHash2,
    //   50000000, // 0.05 SOL max
    //   "Shopify",
    //   3600
    // );
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // // 9. Revoke Intent
    console.log("\n9️⃣ Revoking intent...");
    await revokeIntent(intentPDA);
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // // 10. Update Agent Status
    // console.log("\n🔟 Updating agent status...");
    // await updateAgentStatus(agentPDA, false);
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // await updateAgentStatus(agentPDA, true);
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // // 11. Update Reputation
    // console.log("\n1️⃣1️⃣ Updating reputation...");
    // await updateReputation(agentPDA, 10, "Excellent performance");
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // // 12. Final score check
    // console.log("\n1️⃣2️⃣ Final agent score...");
    // await getAgentScore(agentPDA);

    // console.log("\n✅ All tests completed successfully!");

  } catch (error) {
    console.error("❌ Test failed:", error);
  }
}

// Run tests
runAgentRegistryTests();