//! Stream processing utilities.
//!
//! Provides common stream operations and transformations.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::Stream;
use pin_project_lite::pin_project;
use tokio::time::{sleep, Sleep};

use crate::{StreamError, StreamResult};

/// Extension trait for streams.
pub trait StreamExt: Stream {
    /// Add timeout to stream items.
    fn with_timeout(self, timeout: Duration) -> TimeoutStream<Self>
    where
        Self: Sized,
    {
        TimeoutStream::new(self, timeout)
    }

    /// Buffer stream items.
    fn buffered_batches(self, max_size: usize, max_wait: Duration) -> BatchStream<Self>
    where
        Self: Sized,
        Self::Item: Clone,
    {
        BatchStream::new(self, max_size, max_wait)
    }

    /// Filter and map in one operation.
    fn filter_map_async<F, Fut, U>(self, f: F) -> FilterMapStream<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> Fut,
        Fut: Future<Output = Option<U>>,
    {
        FilterMapStream::new(self, f)
    }
}

impl<S: Stream> StreamExt for S {}

pin_project! {
    /// Stream with per-item timeout.
    pub struct TimeoutStream<S> {
        #[pin]
        inner: S,
        timeout: Duration,
        #[pin]
        deadline: Option<Sleep>,
    }
}

impl<S> TimeoutStream<S> {
    /// Create a new timeout stream.
    pub fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            deadline: None,
        }
    }
}

impl<S: Stream> Stream for TimeoutStream<S> {
    type Item = StreamResult<S::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Initialize deadline if not set
        if this.deadline.is_none() {
            this.deadline.set(Some(sleep(*this.timeout)));
        }

        // Check timeout
        if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
            if deadline.poll(cx).is_ready() {
                return Poll::Ready(Some(Err(StreamError::Timeout(*this.timeout))));
            }
        }

        // Poll inner stream
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                // Reset deadline
                this.deadline.set(Some(sleep(*this.timeout)));
                Poll::Ready(Some(Ok(item)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pin_project! {
    /// Stream that batches items.
    pub struct BatchStream<S: Stream> {
        #[pin]
        inner: S,
        max_size: usize,
        max_wait: Duration,
        batch: Vec<S::Item>,
        #[pin]
        deadline: Option<Sleep>,
    }
}

impl<S: Stream> BatchStream<S>
where
    S::Item: Clone,
{
    /// Create a new batch stream.
    pub fn new(inner: S, max_size: usize, max_wait: Duration) -> Self {
        Self {
            inner,
            max_size,
            max_wait,
            batch: Vec::with_capacity(max_size),
            deadline: None,
        }
    }
}

impl<S: Stream> Stream for BatchStream<S>
where
    S::Item: Clone,
{
    type Item = Vec<S::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            // Check if batch is full
            if this.batch.len() >= *this.max_size {
                let batch = std::mem::take(this.batch);
                *this.batch = Vec::with_capacity(*this.max_size);
                this.deadline.set(None);
                return Poll::Ready(Some(batch));
            }

            // Check timeout
            if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
                if deadline.poll(cx).is_ready() {
                    if !this.batch.is_empty() {
                        let batch = std::mem::take(this.batch);
                        *this.batch = Vec::with_capacity(*this.max_size);
                        this.deadline.set(None);
                        return Poll::Ready(Some(batch));
                    }
                    this.deadline.set(None);
                }
            }

            // Poll inner stream
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    // Start deadline on first item
                    if this.batch.is_empty() && this.deadline.is_none() {
                        this.deadline.set(Some(sleep(*this.max_wait)));
                    }
                    this.batch.push(item);
                }
                Poll::Ready(None) => {
                    // Stream ended, return remaining items
                    if this.batch.is_empty() {
                        return Poll::Ready(None);
                    }
                    let batch = std::mem::take(this.batch);
                    return Poll::Ready(Some(batch));
                }
                Poll::Pending => {
                    // If we have items and deadline passed, return them
                    if !this.batch.is_empty() {
                        if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
                            if deadline.poll(cx).is_ready() {
                                let batch = std::mem::take(this.batch);
                                *this.batch = Vec::with_capacity(*this.max_size);
                                this.deadline.set(None);
                                return Poll::Ready(Some(batch));
                            }
                        }
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

pin_project! {
    /// Async filter-map stream.
    pub struct FilterMapStream<S, F> {
        #[pin]
        inner: S,
        f: F,
    }
}

impl<S, F> FilterMapStream<S, F> {
    /// Create a new filter-map stream.
    pub fn new(inner: S, f: F) -> Self {
        Self { inner, f }
    }
}

/// Counting stream that tracks items processed.
#[derive(Debug)]
pub struct CountingStream<S> {
    inner: S,
    items_count: usize,
}

impl<S> CountingStream<S> {
    /// Create a new counting stream.
    pub fn new(inner: S) -> Self {
        Self { inner, items_count: 0 }
    }

    /// Get the current count of processed items.
    #[must_use]
    pub const fn items_count(&self) -> usize {
        self.items_count
    }
}

impl<S: Stream + Unpin> Stream for CountingStream<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(item)) => {
                self.items_count += 1;
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }
}

/// Rate-limited stream.
pub struct RateLimitedStream<S> {
    inner: S,
    interval: Duration,
    next_allowed: Option<tokio::time::Instant>,
}

impl<S> RateLimitedStream<S> {
    /// Create a new rate-limited stream.
    pub fn new(inner: S, interval: Duration) -> Self {
        Self {
            inner,
            interval,
            next_allowed: None,
        }
    }
}

impl<S: Stream + Unpin> Stream for RateLimitedStream<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let now = tokio::time::Instant::now();

        // Check if we need to wait
        if let Some(next) = self.next_allowed {
            if now < next {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(item)) => {
                self.next_allowed = Some(now + self.interval);
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream::{self, StreamExt as _};
    use tokio::pin;

    #[tokio::test]
    async fn test_counting_stream() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5]);
        let mut counting = CountingStream::new(stream);

        assert_eq!(counting.items_count(), 0);

        while counting.next().await.is_some() {}

        assert_eq!(counting.items_count(), 5);
    }

    #[tokio::test]
    async fn test_timeout_stream_success() {
        let stream = stream::iter(vec![1, 2, 3]);
        let timeout_stream = TimeoutStream::new(stream, Duration::from_secs(1));
        pin!(timeout_stream);

        let mut results = Vec::new();
        while let Some(result) = timeout_stream.next().await {
            results.push(result.unwrap());
        }

        assert_eq!(results, vec![1, 2, 3]);
    }
}
