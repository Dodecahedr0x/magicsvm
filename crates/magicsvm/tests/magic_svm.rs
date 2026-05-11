use {
    magicblock_magic_program_api::{
        args::{
            CommitAndUndelegateArgs, CommitTypeArgs, MagicBaseIntentArgs, MagicIntentBundleArgs,
            UndelegateTypeArgs,
        },
        instruction::MagicBlockInstruction,
    },
    magicsvm::{
        MagicSVM, TransactionTarget, DEFAULT_VALIDATOR_IDENTITY, DELEGATION_PROGRAM_ID,
        MAGIC_CONTEXT_ID, MAGIC_PROGRAM_ID,
    },
    solana_account::ReadableAccount,
    solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction},
    solana_keypair::Keypair,
    solana_message::Message,
    solana_native_token::LAMPORTS_PER_SOL,
    solana_sdk_ids::bpf_loader_upgradeable,
    solana_signer::Signer,
    solana_system_interface::instruction::allocate,
    solana_transaction::Transaction,
    solana_transaction_error::TransactionError,
};

fn schedule_commit_tx(
    payer: &Keypair,
    delegated_account: &Keypair,
    instruction_data: Vec<u8>,
    delegated_account_is_writable: bool,
    blockhash: solana_hash::Hash,
) -> Transaction {
    let delegated_meta = if delegated_account_is_writable {
        AccountMeta::new(delegated_account.pubkey(), false)
    } else {
        AccountMeta::new_readonly(delegated_account.pubkey(), false)
    };

    Transaction::new(
        &[payer],
        Message::new(
            &[Instruction {
                program_id: MAGIC_PROGRAM_ID,
                accounts: vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(MAGIC_CONTEXT_ID, false),
                    delegated_meta,
                ],
                data: instruction_data,
            }],
            Some(&payer.pubkey()),
        ),
        blockhash,
    )
}

#[test_log::test]
fn magic_svm_loads_delegation_program_by_default() {
    let svm = MagicSVM::new();

    let delegation_program = svm.get_account(&DELEGATION_PROGRAM_ID).unwrap();

    assert!(delegation_program.executable);
    assert_eq!(delegation_program.owner, bpf_loader_upgradeable::id());
}

#[test_log::test]
fn magic_svm_loads_magic_program_only_on_ephemeral() {
    let svm = MagicSVM::new();

    assert!(svm
        .get_account_for(TransactionTarget::Base, &MAGIC_PROGRAM_ID)
        .is_none());

    let magic_program = svm
        .get_account_for(TransactionTarget::Ephemeral, &MAGIC_PROGRAM_ID)
        .unwrap();
    assert!(magic_program.executable);
}

#[test_log::test]
fn ephemeral_magic_program_accepts_noop_and_rejects_invalid_data() {
    let payer = Keypair::new();
    let mut svm = MagicSVM::new();
    svm.airdrop(&payer.pubkey(), LAMPORTS_PER_SOL).unwrap();

    let noop = Transaction::new(
        &[&payer],
        Message::new(
            &[Instruction::new_with_bincode(
                MAGIC_PROGRAM_ID,
                &MagicBlockInstruction::Noop(0),
                vec![],
            )],
            Some(&payer.pubkey()),
        ),
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
    );
    svm.send_transaction_to(TransactionTarget::Ephemeral, noop)
        .unwrap();

    svm.expire_blockhash_for(TransactionTarget::Ephemeral);
    let invalid = Transaction::new(
        &[&payer],
        Message::new(
            &[Instruction {
                program_id: MAGIC_PROGRAM_ID,
                accounts: vec![],
                data: vec![0xff],
            }],
            Some(&payer.pubkey()),
        ),
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
    );
    let err = svm
        .send_transaction_to(TransactionTarget::Ephemeral, invalid)
        .unwrap_err()
        .err;
    assert_eq!(
        err,
        TransactionError::InstructionError(0, InstructionError::InvalidInstructionData)
    );
}

#[test_log::test]
fn magic_svm_defaults_to_magicblock_validator_identity() {
    let svm = MagicSVM::new();

    assert_eq!(svm.validator_identity(), DEFAULT_VALIDATOR_IDENTITY);
}

#[test_log::test]
fn magic_svm_can_be_initialized_with_a_validator_identity() {
    let validator = Keypair::new();
    let svm = MagicSVM::new_with_validator_identity(validator.pubkey());

    assert_eq!(svm.validator_identity(), validator.pubkey());
}

#[test_log::test]
fn target_specific_helpers_use_the_selected_ledger() {
    let payer = Keypair::new();
    let delegated = Keypair::new();
    let mut svm = MagicSVM::new();

    let base_airdrop = svm.airdrop(&payer.pubkey(), LAMPORTS_PER_SOL).unwrap();
    assert!(svm
        .get_transaction_for(TransactionTarget::Base, &base_airdrop.signature)
        .is_some());
    assert!(svm
        .get_transaction_for(TransactionTarget::Ephemeral, &base_airdrop.signature)
        .is_none());

    svm.airdrop(&delegated.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.delegate_account(delegated.pubkey()).unwrap();

    let base_blockhash = svm.latest_blockhash_for(TransactionTarget::Base);
    let ephemeral_blockhash = svm.latest_blockhash_for(TransactionTarget::Ephemeral);
    svm.expire_blockhash_for(TransactionTarget::Base);
    assert_ne!(
        svm.latest_blockhash_for(TransactionTarget::Base),
        base_blockhash
    );
    assert_eq!(
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
        ephemeral_blockhash
    );

    let allowed = Transaction::new(
        &[&payer, &delegated],
        Message::new(&[allocate(&delegated.pubkey(), 8)], Some(&payer.pubkey())),
        ephemeral_blockhash,
    );
    let ephemeral_result = svm
        .send_transaction_to(TransactionTarget::Ephemeral, allowed)
        .unwrap();
    assert!(svm
        .get_transaction_for(TransactionTarget::Ephemeral, &ephemeral_result.signature)
        .is_some());
    assert!(svm
        .get_transaction_for(TransactionTarget::Base, &ephemeral_result.signature)
        .is_none());

    assert_eq!(
        svm.get_account_for(TransactionTarget::Base, &delegated.pubkey())
            .unwrap()
            .data
            .len(),
        0
    );
    assert_eq!(
        svm.get_account_for(TransactionTarget::Ephemeral, &delegated.pubkey())
            .unwrap()
            .data
            .len(),
        8
    );
}

#[test_log::test]
fn delegated_accounts_are_mirrored_to_ephemeral_ledger() {
    let delegated = Keypair::new();
    let mut svm = MagicSVM::new();
    svm.airdrop(&delegated.pubkey(), LAMPORTS_PER_SOL).unwrap();

    svm.delegate_account(delegated.pubkey()).unwrap();

    let base_account = svm.get_account(&delegated.pubkey()).unwrap();
    assert_eq!(base_account.owner(), &DELEGATION_PROGRAM_ID);

    let ephemeral_account = svm
        .get_shared_account_for(TransactionTarget::Ephemeral, &delegated.pubkey())
        .unwrap();
    assert!(ephemeral_account.delegated());
    assert!(!ephemeral_account.ephemeral());
    assert!(!ephemeral_account.compressed());
    assert!(!ephemeral_account.confined());
}

#[test_log::test]
fn ephemeral_transactions_can_only_write_delegated_accounts() {
    let payer = Keypair::new();
    let delegated = Keypair::new();
    let non_delegated = Keypair::new();
    let mut svm = MagicSVM::new();
    svm.airdrop(&payer.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.airdrop(&delegated.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.airdrop(&non_delegated.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    svm.delegate_account(delegated.pubkey()).unwrap();

    let allowed = Transaction::new(
        &[&payer, &delegated],
        Message::new(&[allocate(&delegated.pubkey(), 8)], Some(&payer.pubkey())),
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
    );
    assert!(svm
        .send_transaction_to(TransactionTarget::Ephemeral, allowed)
        .is_ok());

    let rejected = Transaction::new(
        &[&payer, &non_delegated],
        Message::new(
            &[allocate(&non_delegated.pubkey(), 8)],
            Some(&payer.pubkey()),
        ),
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
    );
    let err = svm
        .send_transaction_to(TransactionTarget::Ephemeral, rejected)
        .unwrap_err()
        .err;
    assert_eq!(err, TransactionError::InvalidWritableAccount);
}

#[test_log::test]
fn commit_finalize_copies_ephemeral_state_back_to_base() {
    let delegated = Keypair::new();
    let mut svm = MagicSVM::new();
    svm.airdrop(&delegated.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.delegate_account(delegated.pubkey()).unwrap();

    svm.send_transaction_to(
        TransactionTarget::Ephemeral,
        Transaction::new(
            &[&delegated],
            Message::new(
                &[allocate(&delegated.pubkey(), 8)],
                Some(&delegated.pubkey()),
            ),
            svm.latest_blockhash_for(TransactionTarget::Ephemeral),
        ),
    )
    .unwrap();

    svm.commit_account(delegated.pubkey());

    let base_account = svm.get_account(&delegated.pubkey()).unwrap();
    assert_eq!(base_account.data.len(), 8);
}

#[test_log::test]
fn ephemeral_schedule_commit_variants_copy_state_to_base() {
    for instruction_data in [
        bincode::serialize(&MagicBlockInstruction::ScheduleCommit).unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleCommitFinalize {
            request_undelegation: false,
        })
        .unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleBaseIntent(
            MagicBaseIntentArgs::Commit(CommitTypeArgs::Standalone(vec![2])),
        ))
        .unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleBaseIntent(
            MagicBaseIntentArgs::CommitFinalize(CommitTypeArgs::Standalone(vec![2])),
        ))
        .unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleIntentBundle(
            MagicIntentBundleArgs::from(MagicBaseIntentArgs::Commit(CommitTypeArgs::Standalone(
                vec![2],
            ))),
        ))
        .unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleIntentBundle(
            MagicIntentBundleArgs::from(MagicBaseIntentArgs::CommitFinalize(
                CommitTypeArgs::Standalone(vec![2]),
            )),
        ))
        .unwrap(),
    ] {
        let payer = Keypair::new();
        let delegated = Keypair::new();
        let mut svm = MagicSVM::new();
        svm.airdrop(&payer.pubkey(), LAMPORTS_PER_SOL).unwrap();
        svm.airdrop(&delegated.pubkey(), LAMPORTS_PER_SOL).unwrap();
        svm.delegate_account(delegated.pubkey()).unwrap();

        svm.send_transaction_to(
            TransactionTarget::Ephemeral,
            Transaction::new_signed_with_payer(
                &[allocate(&delegated.pubkey(), 8)],
                Some(&delegated.pubkey()),
                &[&delegated],
                svm.latest_blockhash_for(TransactionTarget::Ephemeral),
            ),
        )
        .unwrap();

        assert_eq!(
            svm.get_account_for(TransactionTarget::Ephemeral, &delegated.pubkey())
                .unwrap()
                .data
                .len(),
            8
        );
        assert_eq!(
            svm.get_account_for(TransactionTarget::Base, &delegated.pubkey())
                .unwrap()
                .data
                .len(),
            0
        );

        svm.send_transaction_to(
            TransactionTarget::Ephemeral,
            schedule_commit_tx(
                &payer,
                &delegated,
                instruction_data,
                false,
                svm.latest_blockhash_for(TransactionTarget::Ephemeral),
            ),
        )
        .unwrap();

        let base_account = svm.get_account(&delegated.pubkey()).unwrap();
        assert_eq!(base_account.data.len(), 8);
    }
}

#[test_log::test]
fn ephemeral_schedule_commit_variants_can_undelegate() {
    for instruction_data in [
        bincode::serialize(&MagicBlockInstruction::ScheduleCommitAndUndelegate).unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleCommitFinalize {
            request_undelegation: true,
        })
        .unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleBaseIntent(
            MagicBaseIntentArgs::CommitAndUndelegate(CommitAndUndelegateArgs {
                commit_type: CommitTypeArgs::Standalone(vec![2]),
                undelegate_type: UndelegateTypeArgs::Standalone,
            }),
        ))
        .unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleBaseIntent(
            MagicBaseIntentArgs::CommitFinalizeAndUndelegate(CommitAndUndelegateArgs {
                commit_type: CommitTypeArgs::Standalone(vec![2]),
                undelegate_type: UndelegateTypeArgs::Standalone,
            }),
        ))
        .unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleIntentBundle(
            MagicIntentBundleArgs::from(MagicBaseIntentArgs::CommitAndUndelegate(
                CommitAndUndelegateArgs {
                    commit_type: CommitTypeArgs::Standalone(vec![2]),
                    undelegate_type: UndelegateTypeArgs::Standalone,
                },
            )),
        ))
        .unwrap(),
        bincode::serialize(&MagicBlockInstruction::ScheduleIntentBundle(
            MagicIntentBundleArgs::from(MagicBaseIntentArgs::CommitFinalizeAndUndelegate(
                CommitAndUndelegateArgs {
                    commit_type: CommitTypeArgs::Standalone(vec![2]),
                    undelegate_type: UndelegateTypeArgs::Standalone,
                },
            )),
        ))
        .unwrap(),
    ] {
        let payer = Keypair::new();
        let delegated = Keypair::new();
        let mut svm = MagicSVM::new();
        svm.airdrop(&payer.pubkey(), LAMPORTS_PER_SOL).unwrap();
        svm.airdrop(&delegated.pubkey(), LAMPORTS_PER_SOL).unwrap();
        svm.delegate_account(delegated.pubkey()).unwrap();

        svm.send_transaction_to(
            TransactionTarget::Ephemeral,
            Transaction::new_signed_with_payer(
                &[allocate(&delegated.pubkey(), 8)],
                Some(&delegated.pubkey()),
                &[&delegated],
                svm.latest_blockhash_for(TransactionTarget::Ephemeral),
            ),
        )
        .unwrap();

        assert_eq!(
            svm.get_account_for(TransactionTarget::Ephemeral, &delegated.pubkey())
                .unwrap()
                .data
                .len(),
            8
        );

        assert_eq!(
            svm.get_account_for(TransactionTarget::Base, &delegated.pubkey())
                .unwrap()
                .data
                .len(),
            0
        );

        svm.send_transaction_to(
            TransactionTarget::Ephemeral,
            schedule_commit_tx(
                &payer,
                &delegated,
                instruction_data,
                true,
                svm.latest_blockhash_for(TransactionTarget::Ephemeral),
            ),
        )
        .unwrap();

        let base_account = svm.get_account(&delegated.pubkey()).unwrap();
        assert_eq!(base_account.data.len(), 8);

        svm.expire_blockhash_for(TransactionTarget::Ephemeral);
        let rejected = Transaction::new(
            &[&payer, &delegated],
            Message::new(&[allocate(&delegated.pubkey(), 16)], Some(&payer.pubkey())),
            svm.latest_blockhash_for(TransactionTarget::Ephemeral),
        );
        let err = svm
            .send_transaction_to(TransactionTarget::Ephemeral, rejected)
            .unwrap_err()
            .err;
        assert_eq!(err, TransactionError::InvalidWritableAccount);
    }
}

#[test_log::test]
fn ephemeral_magic_processors_reject_invalid_schedule_commit_accounts() {
    let payer = Keypair::new();
    let schedule_payer = Keypair::new();
    let delegated = Keypair::new();
    let wrong_context = Keypair::new();
    let mut svm = MagicSVM::new();
    svm.airdrop(&payer.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.airdrop(&schedule_payer.pubkey(), LAMPORTS_PER_SOL)
        .unwrap();
    svm.airdrop(&delegated.pubkey(), LAMPORTS_PER_SOL).unwrap();
    svm.delegate_account(delegated.pubkey()).unwrap();

    let wrong_context_tx = Transaction::new_signed_with_payer(
        &[Instruction::new_with_bincode(
            MAGIC_PROGRAM_ID,
            &MagicBlockInstruction::ScheduleCommit,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new_readonly(wrong_context.pubkey(), false),
                AccountMeta::new_readonly(delegated.pubkey(), false),
            ],
        )],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
    );
    let err = svm
        .send_transaction_to(TransactionTarget::Ephemeral, wrong_context_tx)
        .unwrap_err()
        .err;
    assert_eq!(
        err,
        TransactionError::InstructionError(0, InstructionError::MissingAccount)
    );

    svm.expire_blockhash_for(TransactionTarget::Ephemeral);
    let missing_signer_tx = Transaction::new_signed_with_payer(
        &[Instruction::new_with_bincode(
            MAGIC_PROGRAM_ID,
            &MagicBlockInstruction::ScheduleCommit,
            vec![
                AccountMeta::new_readonly(schedule_payer.pubkey(), false),
                AccountMeta::new(MAGIC_CONTEXT_ID, false),
                AccountMeta::new_readonly(delegated.pubkey(), false),
            ],
        )],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
    );
    let err = svm
        .send_transaction_to(TransactionTarget::Ephemeral, missing_signer_tx)
        .unwrap_err()
        .err;
    assert_eq!(
        err,
        TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)
    );

    svm.expire_blockhash_for(TransactionTarget::Ephemeral);
    let no_accounts_tx = Transaction::new_signed_with_payer(
        &[Instruction::new_with_bincode(
            MAGIC_PROGRAM_ID,
            &MagicBlockInstruction::ScheduleCommit,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(MAGIC_CONTEXT_ID, false),
            ],
        )],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
    );
    let err = svm
        .send_transaction_to(TransactionTarget::Ephemeral, no_accounts_tx)
        .unwrap_err()
        .err;
    assert_eq!(
        err,
        TransactionError::InstructionError(0, InstructionError::MissingAccount)
    );

    svm.expire_blockhash_for(TransactionTarget::Ephemeral);
    let readonly_undelegate_tx = schedule_commit_tx(
        &payer,
        &delegated,
        bincode::serialize(&MagicBlockInstruction::ScheduleCommitAndUndelegate).unwrap(),
        false,
        svm.latest_blockhash_for(TransactionTarget::Ephemeral),
    );
    let err = svm
        .send_transaction_to(TransactionTarget::Ephemeral, readonly_undelegate_tx)
        .unwrap_err()
        .err;
    assert_eq!(
        err,
        TransactionError::InstructionError(0, InstructionError::ReadonlyDataModified)
    );
}
