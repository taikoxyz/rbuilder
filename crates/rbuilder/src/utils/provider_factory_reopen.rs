use crate::telemetry::{inc_provider_bad_reopen_counter, inc_provider_reopen_counter};
use reth::providers::{BlockHashReader, ChainSpecProvider, ProviderFactory};
use reth_chainspec::ChainSpec;
use reth_db::database::Database;
use reth_errors::{ProviderError, RethResult};
use reth_primitives::BlockNumber;
use reth_provider::{providers::StaticFileProvider, BlockNumReader, StaticFileProviderFactory};
use std::{
    path::PathBuf, sync::{Arc, Mutex}, thread::sleep, time::Duration
};
use tracing::debug;
use parking_lot::RwLock;

/// This struct is used as a workaround for https://github.com/paradigmxyz/reth/issues/7836
/// it shares one instance of the provider factory that is recreated when inconsistency is detected.
/// This struct should be used on the level of the whole program and ProviderFactory should be extracted from it
/// into the methods that has a lifetime of a slot (e.g. building particular block).
#[derive(Debug, Clone)]
pub struct ProviderFactoryReopener<DB> {
    provider_factory: Arc<Mutex<ProviderFactory<DB>>>,
    chain_spec: Arc<ChainSpec>,
    static_files_path: PathBuf,
    /// Last block the Reopener verified consistency for.
    last_consistent_block: Arc<RwLock<Option<BlockNumber>>>,
    /// Patch to disable checking on test mode. Is ugly but ProviderFactoryReopener should die shortly (5/24/2024).
    testing_mode: bool,
}

impl<DB: Database + Clone> ProviderFactoryReopener<DB> {
    pub fn new(db: DB, chain_spec: Arc<ChainSpec>, static_files_path: PathBuf) -> RethResult<Self> {
        let provider_factory = ProviderFactory::new(
            db,
            chain_spec.clone(),
            StaticFileProvider::read_only(static_files_path.as_path(), true).unwrap(),
        );

        Ok(Self {
            provider_factory: Arc::new(Mutex::new(provider_factory)),
            chain_spec,
            static_files_path,
            last_consistent_block: Arc::new(RwLock::new(None)),
            testing_mode: false,
        })
    }

    pub fn new_from_existing_for_testing(
        provider_factory: ProviderFactory<DB>,
    ) -> RethResult<Self> {
        let chain_spec = provider_factory.chain_spec();
        let static_files_path = provider_factory.static_file_provider().path().to_path_buf();
        Ok(Self {
            provider_factory: Arc::new(Mutex::new(provider_factory)),
            chain_spec,
            static_files_path,
            last_consistent_block: Arc::new(RwLock::new(None)),
            testing_mode: false,
        })
    }

    /// This will currently available provider factory without verifying if its correct, it can be used
    /// when consistency is not absolutely required
    pub fn provider_factory_unchecked(&self) -> ProviderFactory<DB> {
        self.provider_factory.lock().unwrap().clone()
    }

    /// This will check if historical block hashes for the given block is correct and if not it will reopen
    /// provider fatory.
    /// This should be used when consistency is required: e.g. building blocks.
    ///
    /// If the current block number is already known at the time of calling this method, you may pass it to
    /// avoid an additional DB lookup for the latest block number.
    pub fn check_consistency_and_reopen_if_needed(&self) -> eyre::Result<ProviderFactory<DB>> {
        let best_block_number = self
            .provider_factory_unchecked()
            .last_block_number()
            .map_err(|err| eyre::eyre!("Error getting best block number: {:?}", err))?;
        let mut provider_factory = self.provider_factory.lock().unwrap();

        // Don't need to check consistency for the block that was just checked.
        let last_consistent_block = *self.last_consistent_block.read();
        if !self.testing_mode && last_consistent_block != Some(best_block_number) {
            loop {
                match check_provider_factory_health(best_block_number, &provider_factory) {
                    Ok(()) => {
                        break;
                    }
                    Err(err) => {
                        println!("Reopening db {}!", self.chain_spec.chain.id());
                        debug!(?err, "Provider factory is inconsistent, reopening");
                        inc_provider_reopen_counter();

                        // sleep a bit to recover
                        sleep(Duration::from_millis(100));

                        *provider_factory = ProviderFactory::new(
                            provider_factory.db_ref().clone(),
                            self.chain_spec.clone(),
                            StaticFileProvider::read_only(self.static_files_path.as_path(), true)
                                .unwrap(),
                        );
                    }
                }
            }
            // match check_provider_factory_health(best_block_number, &provider_factory) {
            //     Ok(()) => {}
            //     Err(err) => {
            //         inc_provider_bad_reopen_counter();

            //         eyre::bail!(
            //             "Provider factory is inconsistent after reopening: {:?}",
            //             err
            //         );
            //     }
            // }

            *self.last_consistent_block.write() = Some(best_block_number);
        }
        Ok(provider_factory.clone())
    }

    // This will check if historical block hashes for the given block is correct and if not it will reopen
    // provider fatory.
    // This should be used when consistency is required: e.g. building blocks.
    // pub fn check_consistency_and_reopen_if_needed(
    //     &self,
    //     current_block_number: u64,
    // ) -> eyre::Result<ProviderFactory<DB>> {
    //     let best_block_number = self
    //         .provider_factory_unchecked()
    //         .last_block_number()
    //         .map_err(|err| eyre::eyre!("Error getting best block number: {:?}", err))?;
    //     let mut provider_factory = self.provider_factory.lock();

    //     // Don't need to check consistency for the block that was just checked.
    //     let last_consistent_block = *self.last_consistent_block.read();

    //     //tory.lock().unwrap();
    //     if !self.testing_mode {
    //         match check_provider_factory_health(current_block_number, &provider_factory) {
    //             Ok(()) => {}
    //             Err(err) => {
    //                 println!("Reopening DB!");
    //                 debug!(?err, "Provider factory is inconsistent, reopening");
    //                 inc_provider_reopen_counter();

    //                 *provider_factory = ProviderFactory::new(
    //                     provider_factory.db_ref().clone(),
    //                     self.chain_spec.clone(),
    //                     StaticFileProvider::read_only(self.static_files_path.as_path()).unwrap(),
    //                 );
    //             }
    //         }

    //         match check_provider_factory_health(current_block_number, &provider_factory) {
    //             Ok(()) => {}
    //             Err(err) => {
    //                 inc_provider_bad_reopen_counter();

    //                 eyre::bail!(
    //                     "Provider factory is inconsistent after reopening: {:?}",
    //                     err
    //                 );
    //             }
    //         }
    //     }
    //     Ok(provider_factory.clone())
    // }
}

/// Really ugly, should refactor with the string bellow or use better errors.
pub fn is_provider_factory_health_error(report: &eyre::Error) -> bool {
    report
        .to_string()
        .contains("Missing historical block hash for block")
}

#[derive(Debug, thiserror::Error)]
pub enum HistoricalBlockError {
    #[error("ProviderError while checking block hashes: {0}")]
    ProviderError(#[from] ProviderError),
    #[error("Missing historical block hash for block {missing_hash_block}, latest block: {latest_block}")]
    MissingHash {
        missing_hash_block: u64,
        latest_block: u64,
    },
}

/// Here we check if we have all the necessary historical block hashes in the database
/// This was added as a debugging method because static_files storage was not working correctly
/// last_block_number is the number of the latest committed block (i.e. if we build block 1001 it should be 1000)
pub fn check_provider_factory_health<DB: Database>(
    last_block_number: u64,
    reader: &ProviderFactory<DB>,
) -> Result<(), HistoricalBlockError> {
    // evm must have access to block hashes of 256 of the previous blocks
    let blocks_to_check = last_block_number.min(256);
    for i in 0..blocks_to_check {
        let num = last_block_number - i;
        let hash = reader.block_hash(num)?;
        if hash.is_none() {
            return Err(HistoricalBlockError::MissingHash {
                missing_hash_block: num,
                latest_block: last_block_number,
            });
        }
    }

    Ok(())
}

// /// Really ugly, should refactor with the string bellow or use better errors.
// pub fn is_provider_factory_health_error(report: &eyre::Error) -> bool {
//     report
//         .to_string()
//         .contains("Missing historical block hash for block")
// }

// /// Here we check if we have all the necessary historical block hashes in the database
// /// This was added as a debugging method because static_files storage was not working correctly
// pub fn check_provider_factory_health<DB: Database>(
//     current_block_number: u64,
//     provider_factory: &ProviderFactory<DB>,
// ) -> eyre::Result<()> {
//     // evm must have access to block hashed of 256 of the previous blocks
//     for i in 1u64..=256 {
//         let num = current_block_number - i;
//         let hash = provider_factory.block_hash(num)?;
//         if hash.is_none() {
//             //println!(
//             eyre::bail!(
//                 "[{}] Missing historical block hash for block {}, current block: {}",
//                 provider_factory.chain_spec().chain.id(),
//                 current_block_number - i,
//                 current_block_number
//             );
//             break;
//         }

//         if num == 0 {
//             break;
//         }
//     }

//     Ok(())
// }
