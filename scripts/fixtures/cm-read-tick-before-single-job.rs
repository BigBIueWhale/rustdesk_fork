// Test-only read tick from 8fb007cd8b6c3ee404c856e8f3e046b8560e8b2c.
// Original function SHA-256: 4d7c9c67661a0f7a1a4f23819645658ce763a2793c87206073ae54252d835533
use super::*;

pub(super) async fn before_handle_read_jobs_tick(
    jobs: &mut Vec<CmTransferJob>,
    responder: CmFileResponder<'_>,
) -> Result<(), CmEgressAdmissionError> {
    let mut finished = Vec::new();

    for transfer in jobs.iter_mut() {
        let generation = transfer.generation;
        let job = &mut transfer.job;
        if job.is_last_job {
            continue;
        }

        // Initialize data stream if needed (opens file and may produce a digest).
        match init_read_job_for_cm(job, generation).await {
            Ok(Some(response)) => responder.send(response)?,
            Ok(None) => {}
            Err(err) => {
                responder.send(ipc::CmFileResponseKind::ReadError {
                    id: job.id,
                    generation,
                    file_num: job.file_num(),
                    error: err.to_string(),
                })?;
                finished.push((job.id, generation, job.conn_id));
                continue;
            }
        }

        // Read a block from the file
        #[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
        pause_cm_test_read_tick_before_block(job.id, job.conn_id).await;
        match job.read().await {
            Err(err) => {
                responder.send(ipc::CmFileResponseKind::ReadError {
                    id: job.id,
                    generation,
                    file_num: job.file_num(),
                    error: err.to_string(),
                })?;
                finished.push((job.id, generation, job.conn_id));
            }
            Ok(Some(block)) => {
                responder.send(ipc::CmFileResponseKind::ReadBlock {
                    id: block.id,
                    generation,
                    file_num: block.file_num,
                    data: block.data,
                    compressed: block.compressed,
                })?;
            }
            Ok(None) => {
                if job.job_completed() {
                    finished.push((job.id, generation, job.conn_id));
                    match job.job_error() {
                        Some(err) => {
                            responder.send(ipc::CmFileResponseKind::ReadError {
                                id: job.id,
                                generation,
                                file_num: job.file_num(),
                                error: err,
                            })?;
                        }
                        None => {
                            responder.send(ipc::CmFileResponseKind::ReadDone {
                                id: job.id,
                                generation,
                                file_num: job.file_num(),
                            })?;
                        }
                    }
                }
                // else: waiting for confirmation from peer
            }
        }
        // Break to handle jobs one by one.
        break;
    }

    for (id, generation, conn_id) in finished {
        let _ = remove_transfer_job_for_connection(jobs, id, conn_id, generation);
    }

    Ok(())
}
