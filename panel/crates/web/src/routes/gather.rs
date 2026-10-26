//! `asyncio.gather` for manager calls: start every request together, propagate the first failure
//! and leave the other requests running. Dropping a Tokio `JoinHandle` detaches that work, matching
//! Python's non-cancelling gather; `tokio::join!` would instead wait for every sibling.

use tokio::task::JoinHandle;

use crate::http::response::Failure;

pub(crate) enum GatherError<E> {
    Task(Failure),
    Call(E),
}

pub(crate) async fn gathering<T, E>(task: JoinHandle<Result<T, E>>) -> Result<T, GatherError<E>>
where
    T: Send + 'static,
    E: Send + 'static,
{
    match task.await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(GatherError::Call(error)),
        Err(error) => Err(GatherError::Task(Failure::internal(error))),
    }
}
