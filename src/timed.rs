use std::time::{Duration, Instant};

use futures::{try_ready, Async, Future, Poll};

pub struct Timed<Fut, F>
where
    Fut: Future,
    F: FnMut(&Fut::Item, Duration),
{
    inner: Fut,
    f: F,
    start: Option<Instant>,
}

impl<Fut, F> Timed<Fut, F>
where
    Fut: Future,
    F: FnMut(&Fut::Item, Duration),
{
    pub fn elapsed(&mut self) -> Duration {
        self.start.unwrap_or(Instant::now()).elapsed()
    }
}

impl<Fut, F> Future for Timed<Fut, F>
where
    Fut: Future,
    F: FnMut(&Fut::Item, Duration),
{
    type Item = Fut::Item;
    type Error = Fut::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let start = self.start.get_or_insert_with(Instant::now);

        let v = try_ready!(self.inner.poll());

        let elapsed = start.elapsed();
        (self.f)(&v, elapsed);

        Ok(Async::Ready(v))
    }
}

pub trait TimedExt: Sized + Future {
    fn timed<F>(self, f: F) -> Timed<Self, F>
    where
        F: FnMut(&Self::Item, Duration),
    {
        Timed {
            inner: self,
            f,
            start: None,
        }
    }
}

impl<F: Future> TimedExt for F {}
