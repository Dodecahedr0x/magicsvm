use {
    crate::{MAGIC_CONTEXT_ID, MAGIC_PROGRAM_ID},
    magicblock_magic_program_api::{
        args::{
            CommitAndUndelegateArgs, CommitTypeArgs, MagicBaseIntentArgs, MagicIntentBundleArgs,
        },
        instruction::MagicBlockInstruction,
    },
    solana_program_runtime::{declare_process_instruction, invoke_context::InvokeContext},
    solana_transaction::InstructionError,
    solana_transaction_context::{IndexOfAccount, InstructionContext},
};

const DEFAULT_MAGIC_PROGRAM_COMPUTE_UNITS: u64 = 150;
const MAGIC_PAYER_IDX: IndexOfAccount = 0;
const MAGIC_CONTEXT_IDX: IndexOfAccount = 1;
const MAGIC_COMMITTEES_START_IDX: IndexOfAccount = 2;

declare_process_instruction!(
    MagicProgramEntrypoint,
    DEFAULT_MAGIC_PROGRAM_COMPUTE_UNITS,
    |invoke_context| { process_magic_program_instruction(invoke_context) }
);

fn process_magic_program_instruction(
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let instruction_context = invoke_context
        .transaction_context
        .get_current_instruction_context()?;
    match magic_instruction(instruction_context.get_instruction_data())? {
        MagicInstruction::ScheduleCommit => process_schedule_commit(&instruction_context, false),
        MagicInstruction::ScheduleCommitAndUndelegate => {
            process_schedule_commit(&instruction_context, true)
        }
        MagicInstruction::ScheduleCommitFinalize {
            request_undelegation,
        } => process_schedule_commit(&instruction_context, request_undelegation),
        MagicInstruction::ScheduleBaseIntent {
            committed_accounts,
            undelegated_accounts,
        }
        | MagicInstruction::ScheduleIntentBundle {
            committed_accounts,
            undelegated_accounts,
        } => process_schedule_commit_intent(
            &instruction_context,
            &committed_accounts,
            &undelegated_accounts,
        ),
        MagicInstruction::Noop => Ok(()),
    }
}

fn process_schedule_commit(
    instruction_context: &InstructionContext<'_, '_>,
    request_undelegation: bool,
) -> Result<(), InstructionError> {
    validate_magic_schedule_header(instruction_context)?;
    let account_count = instruction_context.get_number_of_instruction_accounts();
    if account_count <= MAGIC_COMMITTEES_START_IDX {
        return Err(InstructionError::MissingAccount);
    }

    let account_indices: Vec<_> = (MAGIC_COMMITTEES_START_IDX..account_count).collect();
    validate_commit_accounts(instruction_context, &account_indices, request_undelegation)
}

fn process_schedule_commit_intent(
    instruction_context: &InstructionContext<'_, '_>,
    committed_accounts: &[u8],
    undelegated_accounts: &[u8],
) -> Result<(), InstructionError> {
    validate_magic_schedule_header(instruction_context)?;
    let committed_accounts: Vec<_> = committed_accounts
        .iter()
        .map(|index| u16::from(*index))
        .collect();
    let undelegated_accounts: Vec<_> = undelegated_accounts
        .iter()
        .map(|index| u16::from(*index))
        .collect();

    validate_commit_accounts(instruction_context, &committed_accounts, false)?;
    validate_commit_accounts(instruction_context, &undelegated_accounts, true)
}

fn validate_magic_schedule_header(
    instruction_context: &InstructionContext<'_, '_>,
) -> Result<(), InstructionError> {
    if instruction_context.get_program_key()? != &MAGIC_PROGRAM_ID {
        return Err(InstructionError::UnsupportedProgramId);
    }
    instruction_context.check_number_of_instruction_accounts(MAGIC_CONTEXT_IDX + 1)?;
    if instruction_context.get_key_of_instruction_account(MAGIC_CONTEXT_IDX)? != &MAGIC_CONTEXT_ID {
        return Err(InstructionError::MissingAccount);
    }
    if !instruction_context.is_instruction_account_signer(MAGIC_PAYER_IDX)? {
        return Err(InstructionError::MissingRequiredSignature);
    }
    if !instruction_context.is_instruction_account_writable(MAGIC_CONTEXT_IDX)? {
        return Err(InstructionError::ReadonlyDataModified);
    }
    Ok(())
}

fn validate_commit_accounts(
    instruction_context: &InstructionContext<'_, '_>,
    account_indices: &[IndexOfAccount],
    request_undelegation: bool,
) -> Result<(), InstructionError> {
    if account_indices.is_empty() {
        return Ok(());
    }

    for account_index in account_indices {
        let account = instruction_context.try_borrow_instruction_account(*account_index)?;
        if account.get_key() == &MAGIC_CONTEXT_ID || account.get_key() == &MAGIC_PROGRAM_ID {
            return Err(InstructionError::MissingAccount);
        }
        if request_undelegation
            && !instruction_context.is_instruction_account_writable(*account_index)?
        {
            return Err(InstructionError::ReadonlyDataModified);
        }
    }
    Ok(())
}

pub enum MagicInstruction {
    ScheduleCommit,
    ScheduleCommitAndUndelegate,
    ScheduleCommitFinalize {
        request_undelegation: bool,
    },
    ScheduleBaseIntent {
        committed_accounts: Vec<u8>,
        undelegated_accounts: Vec<u8>,
    },
    ScheduleIntentBundle {
        committed_accounts: Vec<u8>,
        undelegated_accounts: Vec<u8>,
    },
    Noop,
}

pub fn magic_instruction(data: &[u8]) -> Result<MagicInstruction, InstructionError> {
    let instruction: MagicBlockInstruction =
        bincode::deserialize(data).map_err(|_| InstructionError::InvalidInstructionData)?;
    match instruction {
        MagicBlockInstruction::ScheduleCommit => Ok(MagicInstruction::ScheduleCommit),
        MagicBlockInstruction::ScheduleCommitAndUndelegate => {
            Ok(MagicInstruction::ScheduleCommitAndUndelegate)
        }
        MagicBlockInstruction::ScheduleCommitFinalize {
            request_undelegation,
        } => Ok(MagicInstruction::ScheduleCommitFinalize {
            request_undelegation,
        }),
        MagicBlockInstruction::ScheduleBaseIntent(args) => schedule_base_intent(args),
        MagicBlockInstruction::ScheduleIntentBundle(args) => schedule_intent_bundle(args),
        MagicBlockInstruction::Noop(_) => Ok(MagicInstruction::Noop),
        _ => Err(InstructionError::InvalidInstructionData),
    }
}

fn schedule_base_intent(args: MagicBaseIntentArgs) -> Result<MagicInstruction, InstructionError> {
    match args {
        MagicBaseIntentArgs::Commit(commit_type)
        | MagicBaseIntentArgs::CommitFinalize(commit_type) => {
            Ok(MagicInstruction::ScheduleBaseIntent {
                committed_accounts: commit_type_indices(commit_type),
                undelegated_accounts: Vec::new(),
            })
        }
        MagicBaseIntentArgs::CommitAndUndelegate(args)
        | MagicBaseIntentArgs::CommitFinalizeAndUndelegate(args) => {
            Ok(MagicInstruction::ScheduleBaseIntent {
                committed_accounts: Vec::new(),
                undelegated_accounts: commit_and_undelegate_indices(args),
            })
        }
        MagicBaseIntentArgs::BaseActions(_) => Err(InstructionError::InvalidInstructionData),
    }
}

fn schedule_intent_bundle(
    args: MagicIntentBundleArgs,
) -> Result<MagicInstruction, InstructionError> {
    let mut committed_accounts = Vec::new();
    let mut undelegated_accounts = Vec::new();

    if let Some(commit_type) = args.commit {
        committed_accounts.extend(commit_type_indices(commit_type));
    }
    if let Some(args) = args.commit_and_undelegate {
        undelegated_accounts.extend(commit_and_undelegate_indices(args));
    }
    if let Some(commit_type) = args.commit_finalize {
        committed_accounts.extend(commit_type_indices(commit_type));
    }
    if let Some(args) = args.commit_finalize_and_undelegate {
        undelegated_accounts.extend(commit_and_undelegate_indices(args));
    }

    Ok(MagicInstruction::ScheduleIntentBundle {
        committed_accounts,
        undelegated_accounts,
    })
}

fn commit_type_indices(commit_type: CommitTypeArgs) -> Vec<u8> {
    match commit_type {
        CommitTypeArgs::Standalone(indices) => indices,
        CommitTypeArgs::WithBaseActions {
            committed_accounts, ..
        } => committed_accounts,
    }
}

fn commit_and_undelegate_indices(args: CommitAndUndelegateArgs) -> Vec<u8> {
    commit_type_indices(args.commit_type)
}
