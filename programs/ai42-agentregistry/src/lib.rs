use anchor_lang::prelude::*;

declare_id!("Ew7VbLFKQ5r5G4wdyU93b6oAHxNWf6qmFTpnfbUjWdW3");

#[program]
pub mod ai42_agentregistry {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
