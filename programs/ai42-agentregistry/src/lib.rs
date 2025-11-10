use anchor_lang::prelude::*;
use anchor_lang::solana_program::clock::Clock;
use anchor_lang::solana_program::sysvar::instructions::{
    load_instruction_at_checked, ID as IX_SYSVAR_ID,
};
declare_id!("9npW8cXsqP8jj4eGRDxX45pzXVGMfmYsQMmvncafrJ9N");

const ED25519_PROGRAM_ID: &str = "Ed25519SigVerify111111111111111111111111111";

#[program]
pub mod ai42_agent_registry {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.bump = ctx.bumps.registry;
        registry.authority = ctx.accounts.authority.key();
        registry.total_agents = 0;

        msg!("Agent Registry initialized");
        Ok(())
    }

    pub fn register_agent(
        ctx: Context<RegisterAgent>,
        agent_id: [u8; 32],
        public_key_jwk: String,
        metadata_uri: String,
    ) -> Result<()> {
        require!(public_key_jwk.len() <= 1024, ErrorCode::PublicKeyTooLarge);
        require!(metadata_uri.len() <= 256, ErrorCode::MetadataUriTooLarge);

        let agent = &mut ctx.accounts.agent;
        let registry = &mut ctx.accounts.registry;
        let clock = Clock::get()?;

        agent.agent_id = agent_id;
        agent.owner = ctx.accounts.owner.key();
        agent.public_key_jwk = public_key_jwk;
        agent.reputation_score = 100; // Initial score
        agent.registered_at = clock.unix_timestamp;
        agent.is_active = true;
        agent.total_intents = 0;
        agent.successful_txns = 0;
        agent.failed_txns = 0;
        agent.metadata_uri = metadata_uri;

        registry.total_agents += 1;

        msg!("Agent registered with ID: {:?}", agent_id);
        Ok(())
    }

    pub fn update_agent_status(ctx: Context<UpdateAgentStatus>, is_active: bool) -> Result<()> {
        let agent = &mut ctx.accounts.agent;

        require!(
            ctx.accounts.signer.key() == agent.owner
                || ctx.accounts.signer.key() == ctx.accounts.registry.authority,
            ErrorCode::Unauthorized
        );

        agent.is_active = is_active;

        msg!("Agent status updated to: {}", is_active);
        Ok(())
    }

    pub fn record_intent(
        ctx: Context<RecordIntent>,
        intent_hash: [u8; 32],
        user_signature: Vec<u8>,
        max_amount: u64,
        merchant: String,
        expires_at: i64,
    ) -> Result<()> {
        require!(merchant.len() <= 256, ErrorCode::MerchantNameTooLarge);
        require!(user_signature.len() > 0, ErrorCode::InvalidSignature);

        let intent = &mut ctx.accounts.intent;
        let agent = &mut ctx.accounts.agent;
        let clock = Clock::get()?;

        require!(agent.is_active, ErrorCode::AgentNotActive);
        require!(expires_at > clock.unix_timestamp, ErrorCode::InvalidExpiry);

        intent.intent_hash = intent_hash;
        intent.agent_id = agent.agent_id;
        intent.user = ctx.accounts.user.key();
        intent.user_signature = user_signature;
        intent.max_amount = max_amount;
        intent.merchant = merchant;
        intent.created_at = clock.unix_timestamp;
        intent.expires_at = expires_at;
        intent.executed = false;
        intent.revoked = false;
        intent.execution_tx = None;

        agent.total_intents += 1;

        msg!("Intent recorded with hash: {:?}", intent_hash);
        Ok(())
    }

    pub fn verify_intent(ctx: Context<VerifyIntent>) -> Result<IntentStatus> {
        let intent = &ctx.accounts.intent;
        let clock = Clock::get()?;

        let is_valid =
            !intent.executed && !intent.revoked && clock.unix_timestamp < intent.expires_at;

        let status = IntentStatus {
            is_valid,
            is_expired: clock.unix_timestamp >= intent.expires_at,
            is_executed: intent.executed,
            is_revoked: intent.revoked,
            max_amount: intent.max_amount,
            merchant: intent.merchant.clone(),
        };

        msg!("Intent verified - Valid: {}", is_valid);
        Ok(status)
    }

    pub fn execute_intent(
        ctx: Context<ExecuteIntent>,
        merchant_proof: MerchantProof,
    ) -> Result<()> {
        let intent = &mut ctx.accounts.intent;
        let agent = &mut ctx.accounts.agent;
        let clock = Clock::get()?;

        // Verify intent is valid
        require!(!intent.executed, ErrorCode::IntentAlreadyExecuted);
        require!(!intent.revoked, ErrorCode::IntentRevoked);
        require!(
            clock.unix_timestamp < intent.expires_at,
            ErrorCode::IntentExpired
        );
        require!(agent.agent_id == intent.agent_id, ErrorCode::AgentMismatch);

        // Verify merchant proof
        require!(
            merchant_proof.amount <= intent.max_amount,
            ErrorCode::AmountExceedsLimit
        );

        // Reconstruct the message
        let message = format!(
            "{}{}{}",
            merchant_proof.order_id, merchant_proof.amount, merchant_proof.timestamp
        );

        // Load the Ed25519 instruction
        let ix = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        msg!("Ed25519 instruction data length: {}", ix.data.len());

        // Verify it's the Ed25519 program
        let ed25519_program_id = Pubkey::try_from(ED25519_PROGRAM_ID)
            .map_err(|_| ErrorCode::MissingEd25519Verification)?;

        require!(
            ix.program_id == ed25519_program_id,
            ErrorCode::MissingEd25519Verification
        );

        // Ed25519 instruction format (when using createInstructionWithPublicKey):
        // [num_signatures: u8 = 1]
        // [padding: u8]
        // [signature_offset: u16]
        // [signature_instruction_index: u16]
        // [public_key_offset: u16]
        // [public_key_instruction_index: u16]
        // [message_data_offset: u16]
        // [message_data_size: u16]
        // [message_instruction_index: u16]
        // [public_key: 32 bytes]
        // [signature: 64 bytes]
        // [message: variable bytes]

        require!(ix.data.len() >= 112, ErrorCode::InvalidMerchantProof);

        // Data starts at byte 16 (after 14-byte header + 2 padding)
        let data_start = 16;

        let ix_pubkey: [u8; 32] = ix.data[data_start..data_start + 32]
            .try_into()
            .map_err(|_| ErrorCode::InvalidMerchantProof)?;

        let ix_signature: [u8; 64] = ix.data[data_start + 32..data_start + 96]
            .try_into()
            .map_err(|_| ErrorCode::InvalidMerchantProof)?;

        let ix_message = &ix.data[data_start + 96..];

        msg!("Extracted pubkey: {:?}", &ix_pubkey[..8]);
        msg!(
            "Expected pubkey: {:?}",
            &merchant_proof.merchant_public_key[..8]
        );
        msg!("Extracted message length: {}", ix_message.len());
        msg!("Expected message length: {}", message.as_bytes().len());

        // Verify data matches merchant proof
        require!(
            ix_pubkey == merchant_proof.merchant_public_key,
            ErrorCode::InvalidMerchantProof
        );

        let merchant_sig_array: [u8; 64] = merchant_proof
            .merchant_signature
            .as_slice()
            .try_into()
            .map_err(|_| ErrorCode::InvalidMerchantProof)?;

        require!(
            ix_signature == merchant_sig_array,
            ErrorCode::InvalidMerchantProof
        );

        require!(
            ix_message == message.as_bytes(),
            ErrorCode::InvalidMerchantProof
        );

        msg!("✅ Ed25519 signature verified successfully");

        // If we got here, Ed25519 program verified the signature successfully

        // Mark as executed
        intent.executed = true;
        intent.execution_tx = Some(merchant_proof.order_id.clone());

        // Update agent reputation
        agent.successful_txns += 1;
        agent.reputation_score = agent.reputation_score.saturating_add(1);

        msg!(
            "Intent executed successfully. Order ID: {}",
            merchant_proof.order_id
        );
        Ok(())
    }
    pub fn revoke_intent(ctx: Context<RevokeIntent>) -> Result<()> {
        let intent = &mut ctx.accounts.intent;
        let clock = Clock::get()?;

        require!(
            ctx.accounts.user.key() == intent.user,
            ErrorCode::Unauthorized
        );
        require!(!intent.executed, ErrorCode::IntentAlreadyExecuted);
        require!(
            clock.unix_timestamp < intent.expires_at,
            ErrorCode::IntentExpired
        );

        intent.revoked = true;

        msg!("Intent revoked by user");
        Ok(())
    }

    pub fn update_reputation(
        ctx: Context<UpdateReputation>,
        score_delta: i64,
        reason: String,
    ) -> Result<()> {
        require!(reason.len() <= 256, ErrorCode::ReasonTooLarge);

        let agent = &mut ctx.accounts.agent;

        require!(
            ctx.accounts.authority.key() == ctx.accounts.registry.authority,
            ErrorCode::Unauthorized
        );

        if score_delta < 0 {
            agent.reputation_score = agent
                .reputation_score
                .saturating_sub(score_delta.abs() as u64);
            agent.failed_txns += 1;
        } else {
            agent.reputation_score = agent.reputation_score.saturating_add(score_delta as u64);
        }

        msg!("Reputation updated by {} - Reason: {}", score_delta, reason);
        Ok(())
    }

    pub fn get_agent_score(ctx: Context<GetAgentScore>) -> Result<u64> {
        let agent = &ctx.accounts.agent;
        msg!("Agent score: {}", agent.reputation_score);
        Ok(agent.reputation_score)
    }
}

// ============================================================================
// Account Structures
// ============================================================================

#[account]
pub struct AgentRegistry {
    pub bump: u8,
    pub authority: Pubkey,
    pub total_agents: u64,
}

#[account]
pub struct Agent {
    pub agent_id: [u8; 32],
    pub owner: Pubkey,
    pub public_key_jwk: String,
    pub reputation_score: u64,
    pub registered_at: i64,
    pub is_active: bool,
    pub total_intents: u64,
    pub successful_txns: u64,
    pub failed_txns: u64,
    pub metadata_uri: String,
}

#[account]
pub struct Intent {
    pub intent_hash: [u8; 32],
    pub agent_id: [u8; 32],
    pub user: Pubkey,
    pub user_signature: Vec<u8>,
    pub max_amount: u64,
    pub merchant: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub executed: bool,
    pub revoked: bool,
    pub execution_tx: Option<String>,
}

// ============================================================================
// Context Structures
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 1 + 32 + 8,
        seeds = [b"registry"],
        bump
    )]
    pub registry: Account<'info, AgentRegistry>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(agent_id: [u8; 32])]
pub struct RegisterAgent<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 32 + 1024 + 8 + 8 + 1 + 8 + 8 + 8 + 256,
        seeds = [b"agent", agent_id.as_ref()],
        bump
    )]
    pub agent: Account<'info, Agent>,

    #[account(mut, seeds = [b"registry"], bump = registry.bump)]
    pub registry: Account<'info, AgentRegistry>,

    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAgentStatus<'info> {
    #[account(mut)]
    pub agent: Account<'info, Agent>,

    #[account(seeds = [b"registry"], bump = registry.bump)]
    pub registry: Account<'info, AgentRegistry>,

    pub signer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(intent_hash: [u8; 32])]
pub struct RecordIntent<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 32 + 32 + 32 + 256 + 8 + 256 + 8 + 8 + 1 + 1 + 256,
        seeds = [b"intent", intent_hash.as_ref()],
        bump
    )]
    pub intent: Account<'info, Intent>,

    #[account(mut)]
    pub agent: Account<'info, Agent>,

    /// CHECK: User pubkey for intent authorization
    pub user: AccountInfo<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyIntent<'info> {
    pub intent: Account<'info, Intent>,
}

#[derive(Accounts)]
pub struct ExecuteIntent<'info> {
    #[account(mut)]
    pub intent: Account<'info, Intent>,

    #[account(mut)]
    pub agent: Account<'info, Agent>,

    pub executor: Signer<'info>,

    /// CHECK: Instructions sysvar for Ed25519 signature verification
    #[account(address = IX_SYSVAR_ID)]
    pub ix_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct RevokeIntent<'info> {
    #[account(mut)]
    pub intent: Account<'info, Intent>,

    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateReputation<'info> {
    #[account(mut)]
    pub agent: Account<'info, Agent>,

    #[account(seeds = [b"registry"], bump = registry.bump)]
    pub registry: Account<'info, AgentRegistry>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct GetAgentScore<'info> {
    pub agent: Account<'info, Agent>,
}

// ============================================================================
// Data Structures
// ============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct MerchantProof {
    pub order_id: String,
    pub amount: u64,
    pub timestamp: i64,
    pub merchant_signature: Vec<u8>,
    pub merchant_public_key: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct IntentStatus {
    pub is_valid: bool,
    pub is_expired: bool,
    pub is_executed: bool,
    pub is_revoked: bool,
    pub max_amount: u64,
    pub merchant: String,
}

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Intent has already been executed")]
    IntentAlreadyExecuted,

    #[msg("Intent has been revoked by user")]
    IntentRevoked,

    #[msg("Intent has expired")]
    IntentExpired,

    #[msg("Invalid signature provided")]
    InvalidSignature,

    #[msg("Amount exceeds maximum allowed")]
    AmountExceedsLimit,

    #[msg("Unauthorized access")]
    Unauthorized,

    #[msg("Agent is not active")]
    AgentNotActive,

    #[msg("Agent ID mismatch")]
    AgentMismatch,

    #[msg("Invalid merchant proof")]
    InvalidMerchantProof,

    #[msg("Public key too large (max 1024 bytes)")]
    PublicKeyTooLarge,

    #[msg("Metadata URI too large (max 256 bytes)")]
    MetadataUriTooLarge,

    #[msg("Merchant name too large (max 256 bytes)")]
    MerchantNameTooLarge,

    #[msg("Reason too large (max 256 bytes)")]
    ReasonTooLarge,

    #[msg("Invalid expiry timestamp")]
    InvalidExpiry,

    #[msg("Ed25519 signature verification instruction missing or invalid")]
    MissingEd25519Verification,
}
