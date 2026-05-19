use {
    crate::{
        error::LiteSVMError,
        magic::magic_program::{magic_instruction, MagicInstruction, MagicProgramEntrypoint},
        types::{FailedTransactionMetadata, TransactionMetadata, TransactionResult},
        LiteSVM,
    },
    borsh::BorshDeserialize,
    dlp_api::{
        args::{
            DelegateWithActionsArgs, MaybeEncryptedAccountMeta, MaybeEncryptedIxData,
            MaybeEncryptedPubkey, PostDelegationActions,
        },
        compact,
        discriminator::DlpDiscriminator,
        encryption::{self, KEY_LEN},
        state::DelegationRecord,
    },
    solana_account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
    solana_address::Address,
    solana_hash::Hash,
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_transaction::{versioned::VersionedTransaction, InstructionError, Transaction},
    solana_transaction_error::TransactionError,
    std::{
        collections::HashSet,
        ops::{Deref, DerefMut},
        path::Path,
    },
};

mod magic_program;

pub const DELEGATION_PROGRAM_ID: Address = Address::new_from_array(dlp_api::ID.to_bytes());
pub const MAGIC_PROGRAM_ID: Address =
    Address::new_from_array(magicblock_magic_program_api::ID.to_bytes());
pub const MAGIC_CONTEXT_ID: Address =
    Address::new_from_array(magicblock_magic_program_api::MAGIC_CONTEXT_PUBKEY.to_bytes());
pub const DEFAULT_VALIDATOR_IDENTITY: &str =
    "9Vo7TbA5YfC5a33JhAi9Fb41usA6JwecHNRw3f9MzzHAM8hFnXTzL5DcEHwsAFjuUZ8vNQcJ4XziRFpMc3gTgBQ";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionTarget {
    Base,
    Ephemeral,
}

pub struct MagicSVM {
    base: LiteSVM,
    ephemeral: LiteSVM,
    validator_keypair: Keypair,
    delegated_accounts: HashSet<Address>,
}

impl Default for MagicSVM {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for MagicSVM {
    type Target = LiteSVM;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for MagicSVM {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl MagicSVM {
    pub fn new() -> Self {
        Self::new_with_validator_identity(Keypair::from_base58_string(DEFAULT_VALIDATOR_IDENTITY))
    }

    pub fn new_with_validator_identity(validator_keypair: Keypair) -> Self {
        let base = LiteSVM::new();
        let mut ephemeral = LiteSVM::new();
        ephemeral.add_builtin(MAGIC_PROGRAM_ID, MagicProgramEntrypoint::vm);
        ephemeral
            .set_account(
                MAGIC_CONTEXT_ID,
                Account {
                    lamports: 1,
                    owner: MAGIC_PROGRAM_ID,
                    ..Default::default()
                },
            )
            .unwrap();

        Self {
            base,
            ephemeral,
            validator_keypair,
            delegated_accounts: HashSet::new(),
        }
    }

    pub fn validator_keypair(&self) -> &Keypair {
        &self.validator_keypair
    }

    pub fn validator_identity(&self) -> Address {
        self.validator_keypair.pubkey()
    }

    pub fn base(&self) -> &LiteSVM {
        &self.base
    }

    pub fn base_mut(&mut self) -> &mut LiteSVM {
        &mut self.base
    }

    pub fn ephemeral(&self) -> &LiteSVM {
        &self.ephemeral
    }

    pub fn ephemeral_mut(&mut self) -> &mut LiteSVM {
        &mut self.ephemeral
    }

    pub fn get_account(&self, pubkey: &Address) -> Option<Account> {
        self.get_account_for(TransactionTarget::Base, pubkey)
    }

    pub fn get_account_for(&self, target: TransactionTarget, pubkey: &Address) -> Option<Account> {
        match target {
            TransactionTarget::Base => self.base.get_account(pubkey),
            TransactionTarget::Ephemeral => self.ephemeral.get_account(pubkey),
        }
    }

    pub fn get_shared_account_for(
        &self,
        target: TransactionTarget,
        pubkey: &Address,
    ) -> Option<AccountSharedData> {
        match target {
            TransactionTarget::Base => self.base.accounts.get_account(pubkey),
            TransactionTarget::Ephemeral => self.ephemeral.accounts.get_account(pubkey),
        }
    }

    pub fn set_account(&mut self, pubkey: Address, account: Account) -> Result<(), LiteSVMError> {
        self.base.set_account(pubkey, account)
    }

    pub fn get_balance(&self, pubkey: &Address) -> Option<u64> {
        self.base.get_balance(pubkey)
    }

    pub fn latest_blockhash(&self) -> Hash {
        self.base.latest_blockhash()
    }

    pub fn latest_blockhash_for(&self, target: TransactionTarget) -> Hash {
        match target {
            TransactionTarget::Base => self.base.latest_blockhash(),
            TransactionTarget::Ephemeral => self.ephemeral.latest_blockhash(),
        }
    }

    pub fn get_transaction_for(
        &self,
        target: TransactionTarget,
        signature: &Signature,
    ) -> Option<&TransactionResult> {
        match target {
            TransactionTarget::Base => self.base.get_transaction(signature),
            TransactionTarget::Ephemeral => self.ephemeral.get_transaction(signature),
        }
    }

    pub fn expire_blockhash_for(&mut self, target: TransactionTarget) {
        match target {
            TransactionTarget::Base => self.base.expire_blockhash(),
            TransactionTarget::Ephemeral => self.ephemeral.expire_blockhash(),
        }
    }

    pub fn airdrop(&mut self, pubkey: &Address, lamports: u64) -> TransactionResult {
        self.base.airdrop(pubkey, lamports)
    }

    pub fn add_program(
        &mut self,
        program_id: Address,
        program_bytes: &[u8],
    ) -> Result<(), LiteSVMError> {
        self.base.add_program(program_id, program_bytes)?;
        self.ephemeral.add_program(program_id, program_bytes)
    }

    pub fn add_program_from_file(
        &mut self,
        program_id: Address,
        path: impl AsRef<Path>,
    ) -> Result<(), LiteSVMError> {
        let program_bytes = std::fs::read(path).map_err(LiteSVMError::InvalidPath)?;
        self.add_program(program_id, &program_bytes)
    }

    pub fn add_program_with_loader(
        &mut self,
        program_id: Address,
        program_bytes: &[u8],
        loader_id: Address,
    ) -> Result<(), LiteSVMError> {
        self.base
            .add_program_with_loader(program_id, program_bytes, loader_id)?;
        self.ephemeral
            .add_program_with_loader(program_id, program_bytes, loader_id)
    }

    pub fn send_transaction(&mut self, tx: impl Into<VersionedTransaction>) -> TransactionResult {
        self.send_transaction_to(TransactionTarget::Base, tx)
    }

    pub fn send_transaction_to(
        &mut self,
        target: TransactionTarget,
        tx: impl Into<VersionedTransaction>,
    ) -> TransactionResult {
        let vtx = tx.into();
        match target {
            TransactionTarget::Base => {
                let effects = MagicTransactionEffects::from_message(&vtx.message);
                let writable_accounts = writable_accounts_from_message(&vtx.message);
                let result = self.base.send_transaction(vtx);
                if let Ok(meta) = result {
                    if let Err(err) = self.apply_base_effects(effects) {
                        return Err(FailedTransactionMetadata { err, meta });
                    }
                    self.apply_base_account_state(&writable_accounts);
                    Ok(meta)
                } else {
                    result
                }
            }
            TransactionTarget::Ephemeral => {
                if let Err(err) = self.check_ephemeral_writable_accounts(&vtx.message) {
                    return failed_transaction(err);
                }
                self.sync_ephemeral_fee_payer(&vtx.message);
                let message = vtx.message.clone();
                let result = self.ephemeral.send_transaction(vtx);
                if let Ok(meta) = &result {
                    let effects = MagicTransactionEffects::from_ephemeral_message_and_metadata(
                        &message, meta,
                    );
                    if let Err(err) = self.apply_base_effects(effects) {
                        return Err(FailedTransactionMetadata {
                            err,
                            meta: meta.clone(),
                        });
                    }
                }
                result
            }
        }
    }

    pub fn simulate_transaction_to(
        &mut self,
        target: TransactionTarget,
        tx: impl Into<VersionedTransaction>,
    ) -> std::result::Result<crate::types::SimulatedTransactionInfo, FailedTransactionMetadata>
    {
        let vtx = tx.into();
        match target {
            TransactionTarget::Base => self.base.simulate_transaction(vtx),
            TransactionTarget::Ephemeral => {
                if let Err(err) = self.check_ephemeral_writable_accounts(&vtx.message) {
                    return Err(FailedTransactionMetadata {
                        err,
                        meta: Default::default(),
                    });
                }
                self.ephemeral.simulate_transaction(vtx)
            }
        }
    }

    pub fn delegate_account(&mut self, delegated_account: Address) -> Result<(), TransactionError> {
        let Some(mut base_account) = self.base.accounts.get_account(&delegated_account) else {
            return Err(TransactionError::AccountNotFound);
        };
        let original_owner = {
            let record_address = dlp_api::pda::delegation_record_pda_from_delegated_account(
                &delegated_account.to_bytes().into(),
            );
            if let Some(account) = self.base.get_account(&record_address.to_bytes().into()) {
                DelegationRecord::try_from_bytes_with_discriminator(&account.data)
                    .map(|rec| rec.owner.to_bytes().into())
                    .ok()
            } else {
                None
            }
            .unwrap_or(*base_account.owner())
        };
        base_account.set_owner(DELEGATION_PROGRAM_ID);
        self.base
            .accounts
            .add_account(delegated_account, base_account.clone())
            .map_err(|_| TransactionError::InvalidAccountIndex)?;

        base_account.set_delegated(true);
        base_account.set_owner(original_owner);
        self.ephemeral
            .accounts
            .add_account(delegated_account, base_account)
            .map_err(|_| TransactionError::InvalidAccountIndex)?;
        self.delegated_accounts.insert(delegated_account);
        Ok(())
    }

    pub fn commit_account(&mut self, delegated_account: Address) {
        let Some(ephemeral_account) = self.ephemeral.accounts.get_account(&delegated_account)
        else {
            return;
        };
        let _ = self
            .base
            .accounts
            .add_account(delegated_account, ephemeral_account);
    }

    pub fn undelegate_account(&mut self, delegated_account: Address) {
        self.delegated_accounts.remove(&delegated_account);
        if let Some(mut base_account) = self.base.accounts.get_account(&delegated_account) {
            base_account.set_delegated(false);
            base_account.set_undelegating(false);
            let _ = self
                .base
                .accounts
                .add_account(delegated_account, base_account);
        }
    }

    fn check_ephemeral_writable_accounts(
        &self,
        message: &VersionedMessage,
    ) -> Result<(), TransactionError> {
        for (index, key) in message.static_account_keys().iter().enumerate() {
            if message.is_maybe_writable(index, None)
                && !self.is_ephemeral_writable_exception(index, key)
                && !self.delegated_accounts.contains(key)
            {
                return Err(TransactionError::InvalidWritableAccount);
            }
        }
        Ok(())
    }

    fn is_ephemeral_writable_exception(&self, account_index: usize, key: &Address) -> bool {
        account_index == 0 || *key == MAGIC_CONTEXT_ID
    }

    fn sync_ephemeral_fee_payer(&mut self, message: &VersionedMessage) {
        let Some(fee_payer) = message.static_account_keys().first() else {
            return;
        };
        if self.ephemeral.accounts.get_account(fee_payer).is_some() {
            return;
        }
        if let Some(account) = self.base.accounts.get_account(fee_payer) {
            let _ = self.ephemeral.accounts.add_account(*fee_payer, account);
        }
    }

    fn apply_base_effects(
        &mut self,
        effects: MagicTransactionEffects,
    ) -> Result<(), TransactionError> {
        for delegation in effects.delegated_accounts {
            if self.delegate_account(delegation.account).is_ok() {
                self.run_post_delegation_actions(delegation.actions)?;
            }
        }
        for account in effects.committed_accounts {
            self.commit_account(account);
        }
        for account in effects.undelegated_accounts {
            self.commit_account(account);
            self.undelegate_account(account);
        }
        Ok(())
    }

    fn run_post_delegation_actions(
        &mut self,
        actions: Option<PostDelegationActions>,
    ) -> Result<(), TransactionError> {
        let Some(actions) = actions else {
            return Ok(());
        };

        let instructions = decrypt_post_delegation_instructions(
            actions,
            &self.validator_identity().to_bytes(),
            &self.validator_keypair.to_bytes(),
        )?;
        let Some(payer) = instructions
            .iter()
            .flat_map(|instruction| instruction.accounts.iter())
            .find(|account| account.is_signer)
            .map(|account| account.pubkey)
        else {
            return Err(post_delegation_action_error());
        };
        let message = Message::new_with_blockhash(
            &instructions,
            Some(&payer),
            &self.ephemeral.latest_blockhash(),
        );
        let tx = Transaction::new_unsigned(message);
        let sigverify = self.ephemeral.get_sigverify();
        self.ephemeral.set_sigverify(false);
        let result = self.send_transaction_to(TransactionTarget::Ephemeral, tx);
        self.ephemeral.set_sigverify(sigverify);
        result.map(|_| ()).map_err(|err| err.err)
    }

    fn apply_base_account_state(&mut self, writable_accounts: &[Address]) {
        for account in writable_accounts {
            if self.has_delegation_metadata_for(account) {
                let _ = self.delegate_account(*account);
            } else if self.delegated_accounts.contains(account)
                && self
                    .base
                    .accounts
                    .get_account(account)
                    .is_some_and(|account| *account.owner() != DELEGATION_PROGRAM_ID)
            {
                self.undelegate_account(*account);
            }
        }
    }

    fn has_delegation_metadata_for(&self, delegated_account: &Address) -> bool {
        let metadata = Address::find_program_address(
            &[b"delegation-metadata", delegated_account.as_ref()],
            &DELEGATION_PROGRAM_ID,
        )
        .0;
        self.base
            .accounts
            .get_account(&metadata)
            .is_some_and(|account| *account.owner() == DELEGATION_PROGRAM_ID)
    }
}

fn failed_transaction(err: TransactionError) -> TransactionResult {
    Err(FailedTransactionMetadata {
        err,
        meta: Default::default(),
    })
}

#[derive(Debug)]
struct DelegationEffect {
    account: Address,
    actions: Option<PostDelegationActions>,
}

#[derive(Default, Debug)]
struct MagicTransactionEffects {
    delegated_accounts: Vec<DelegationEffect>,
    committed_accounts: Vec<Address>,
    undelegated_accounts: Vec<Address>,
}

impl MagicTransactionEffects {
    fn from_message(message: &VersionedMessage) -> Self {
        let account_keys = message.static_account_keys();
        let mut effects = Self::default();

        for instruction in message.instructions() {
            let Some(program_id) = account_keys.get(usize::from(instruction.program_id_index))
            else {
                continue;
            };
            if *program_id != DELEGATION_PROGRAM_ID {
                continue;
            }
            let Some(discriminator) = instruction_discriminator(&instruction.data) else {
                continue;
            };
            match discriminator {
                DlpDiscriminator::Delegate
                | DlpDiscriminator::DelegateWithAnyValidator
                | DlpDiscriminator::DelegateWithActions => {
                    if let Some(account) = instruction
                        .accounts
                        .get(1)
                        .and_then(|index| account_keys.get(usize::from(*index)))
                    {
                        effects.delegated_accounts.push(DelegationEffect {
                            account: *account,
                            actions: post_delegation_actions(discriminator, &instruction.data),
                        });
                    }
                }
                DlpDiscriminator::CommitState
                | DlpDiscriminator::Finalize
                | DlpDiscriminator::CommitStateFromBuffer
                | DlpDiscriminator::CommitDiff
                | DlpDiscriminator::CommitDiffFromBuffer
                | DlpDiscriminator::CommitFinalize
                | DlpDiscriminator::CommitFinalizeFromBuffer => {
                    if let Some(account) = instruction
                        .accounts
                        .get(1)
                        .and_then(|index| account_keys.get(usize::from(*index)))
                    {
                        effects.committed_accounts.push(*account);
                    }
                }
                DlpDiscriminator::Undelegate | DlpDiscriminator::UndelegateConfinedAccount => {
                    if let Some(account) = instruction
                        .accounts
                        .get(1)
                        .and_then(|index| account_keys.get(usize::from(*index)))
                    {
                        effects.undelegated_accounts.push(*account);
                    }
                }
                _ => {}
            }
        }

        effects
    }

    fn from_ephemeral_message(message: &VersionedMessage) -> Self {
        let account_keys = message.static_account_keys();
        let mut effects = Self::default();

        for instruction in message.instructions() {
            Self::record_magic_instruction(
                instruction.program_id_index,
                &instruction.accounts,
                &instruction.data,
                account_keys,
                &mut effects,
            );
        }

        effects
    }

    fn from_ephemeral_message_and_metadata(
        message: &VersionedMessage,
        meta: &TransactionMetadata,
    ) -> Self {
        let account_keys = message.static_account_keys();
        let mut effects = Self::from_ephemeral_message(message);

        for inner_instruction in meta.inner_instructions.iter().flatten() {
            let instruction = &inner_instruction.instruction;
            Self::record_magic_instruction(
                instruction.program_id_index,
                &instruction.accounts,
                &instruction.data,
                account_keys,
                &mut effects,
            );
        }

        effects
    }

    fn record_magic_instruction(
        program_id_index: u8,
        instruction_accounts: &[u8],
        instruction_data: &[u8],
        account_keys: &[Address],
        effects: &mut Self,
    ) {
        let Some(program_id) = account_keys.get(usize::from(program_id_index)) else {
            return;
        };
        if *program_id != MAGIC_PROGRAM_ID {
            return;
        }
        let Ok(magic_ix) = magic_instruction(instruction_data) else {
            return;
        };

        let accounts = instruction_accounts
            .iter()
            .skip(2)
            .filter_map(|index| account_keys.get(usize::from(*index)).copied());

        match magic_ix {
            MagicInstruction::ScheduleCommit
            | MagicInstruction::ScheduleCommitFinalize {
                request_undelegation: false,
            } => effects.committed_accounts.extend(accounts),
            MagicInstruction::ScheduleCommitAndUndelegate
            | MagicInstruction::ScheduleCommitFinalize {
                request_undelegation: true,
            } => effects.undelegated_accounts.extend(accounts),
            MagicInstruction::ScheduleBaseIntent {
                committed_accounts,
                undelegated_accounts,
            }
            | MagicInstruction::ScheduleIntentBundle {
                committed_accounts,
                undelegated_accounts,
            } => {
                effects
                    .committed_accounts
                    .extend(committed_accounts.into_iter().filter_map(|index| {
                        instruction_accounts
                            .get(usize::from(index))
                            .and_then(|account_index| account_keys.get(usize::from(*account_index)))
                            .copied()
                    }));
                effects
                    .undelegated_accounts
                    .extend(undelegated_accounts.into_iter().filter_map(|index| {
                        instruction_accounts
                            .get(usize::from(index))
                            .and_then(|account_index| account_keys.get(usize::from(*account_index)))
                            .copied()
                    }));
            }
            MagicInstruction::Noop => {}
        }
    }
}

fn writable_accounts_from_message(message: &VersionedMessage) -> Vec<Address> {
    message
        .static_account_keys()
        .iter()
        .enumerate()
        .filter_map(|(index, key)| {
            (index != 0 && message.is_maybe_writable(index, None)).then_some(*key)
        })
        .collect()
}

fn post_delegation_actions(
    discriminator: DlpDiscriminator,
    instruction_data: &[u8],
) -> Option<PostDelegationActions> {
    if discriminator != DlpDiscriminator::DelegateWithActions {
        return None;
    }

    DelegateWithActionsArgs::try_from_slice(instruction_data.get(8..)?)
        .ok()
        .map(|args| args.actions)
}

fn decrypt_post_delegation_instructions(
    actions: PostDelegationActions,
    validator_pubkey: &[u8; KEY_LEN],
    validator_secret: &[u8],
) -> Result<Vec<Instruction>, TransactionError> {
    let validator_x25519_pubkey = encryption::ed25519_pubkey_to_x25519(validator_pubkey)
        .map_err(|_| post_delegation_action_error())?;
    let validator_x25519_secret = encryption::ed25519_secret_to_x25519(validator_secret)
        .map_err(|_| post_delegation_action_error())?;
    let mut pubkeys: Vec<Address> = actions
        .signers
        .iter()
        .map(|pubkey| Address::new_from_array(*pubkey))
        .collect();
    for pubkey in actions.non_signers {
        pubkeys.push(decrypt_post_delegation_pubkey(
            pubkey,
            &validator_x25519_pubkey,
            &validator_x25519_secret,
        )?);
    }

    actions
        .instructions
        .into_iter()
        .map(|instruction| {
            let program_id = resolve_post_delegation_pubkey(&pubkeys, instruction.program_id)?;
            let accounts = instruction
                .accounts
                .into_iter()
                .map(|account| {
                    decrypt_post_delegation_account_meta(
                        &pubkeys,
                        account,
                        &validator_x25519_pubkey,
                        &validator_x25519_secret,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let data = decrypt_post_delegation_data(
                instruction.data,
                &validator_x25519_pubkey,
                &validator_x25519_secret,
            )?;

            Ok(Instruction {
                program_id,
                accounts,
                data,
            })
        })
        .collect()
}

fn decrypt_post_delegation_pubkey(
    pubkey: MaybeEncryptedPubkey,
    validator_x25519_pubkey: &[u8; KEY_LEN],
    validator_x25519_secret: &[u8; KEY_LEN],
) -> Result<Address, TransactionError> {
    match pubkey {
        MaybeEncryptedPubkey::ClearText(pubkey) => Ok(Address::new_from_array(pubkey)),
        MaybeEncryptedPubkey::Encrypted(buffer) => {
            let decrypted = encryption::decrypt(
                buffer.as_bytes(),
                validator_x25519_pubkey,
                validator_x25519_secret,
            )
            .map_err(|_| post_delegation_action_error())?;
            let pubkey = <[u8; KEY_LEN]>::try_from(decrypted.as_slice())
                .map_err(|_| post_delegation_action_error())?;
            Ok(Address::new_from_array(pubkey))
        }
    }
}

fn decrypt_post_delegation_account_meta(
    pubkeys: &[Address],
    account: MaybeEncryptedAccountMeta,
    validator_x25519_pubkey: &[u8; KEY_LEN],
    validator_x25519_secret: &[u8; KEY_LEN],
) -> Result<AccountMeta, TransactionError> {
    let account = match account {
        MaybeEncryptedAccountMeta::ClearText(account) => account,
        MaybeEncryptedAccountMeta::Encrypted(buffer) => {
            let decrypted = encryption::decrypt(
                buffer.as_bytes(),
                validator_x25519_pubkey,
                validator_x25519_secret,
            )
            .map_err(|_| post_delegation_action_error())?;
            if decrypted.len() != 1 {
                return Err(post_delegation_action_error());
            }
            compact::AccountMeta::from_byte(decrypted[0])
                .ok_or_else(post_delegation_action_error)?
        }
    };
    let pubkey = resolve_post_delegation_pubkey(pubkeys, account.key())?;

    Ok(if account.is_writable() {
        AccountMeta::new(pubkey, account.is_signer())
    } else {
        AccountMeta::new_readonly(pubkey, account.is_signer())
    })
}

fn decrypt_post_delegation_data(
    data: MaybeEncryptedIxData,
    validator_x25519_pubkey: &[u8; KEY_LEN],
    validator_x25519_secret: &[u8; KEY_LEN],
) -> Result<Vec<u8>, TransactionError> {
    let mut decrypted_data = data.prefix;
    if !data.suffix.as_bytes().is_empty() {
        decrypted_data.extend_from_slice(
            &encryption::decrypt(
                data.suffix.as_bytes(),
                validator_x25519_pubkey,
                validator_x25519_secret,
            )
            .map_err(|_| post_delegation_action_error())?,
        );
    }
    Ok(decrypted_data)
}

fn resolve_post_delegation_pubkey(
    pubkeys: &[Address],
    index: u8,
) -> Result<Address, TransactionError> {
    pubkeys
        .get(usize::from(index))
        .copied()
        .ok_or_else(post_delegation_action_error)
}

fn post_delegation_action_error() -> TransactionError {
    TransactionError::InstructionError(0, InstructionError::InvalidInstructionData)
}

fn instruction_discriminator(data: &[u8]) -> Option<DlpDiscriminator> {
    let bytes = data.get(..8)?;
    let discriminator = u64::from_le_bytes(bytes.try_into().ok()?);
    u8::try_from(discriminator).ok()?.try_into().ok()
}
