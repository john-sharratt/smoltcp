use core::task::Waker;

/// Linked list of wakers to be woken
#[derive(Debug)]
struct WakerNext {
    waker: Waker,
    next: Option<Box<WakerNext>>,
}

/// Utility struct to register and wake a waker.
#[derive(Debug)]
pub struct WakerRegistration {
    waker: Option<WakerNext>,
}
impl Drop
for WakerRegistration {
    fn drop(&mut self) {
        self.wake_all()
    }
}

impl WakerRegistration {
    pub const fn new() -> Self {
        Self { waker: None }
    }

    /// Register a waker. Overwrites the previous waker, if any.
    pub fn register(&mut self, w: &Waker) {
        match self.waker {
            // Optimization: If both the old and new Wakers wake the same task, we can simply
            // keep the old waker, skipping the clone. (In most executor implementations,
            // cloning a waker is somewhat expensive, comparable to cloning an Arc).
            Some(ref w2) if (w2.waker.will_wake(w)) => {}
            // In all other cases
            // - we have no waker registered
            // - we have a waker registered but it's for a different task.
            // then clone the new waker and store it
            _ => self.waker = Some(WakerNext {
                waker: w.clone(),
                next: None
            }),
        }
    }

    /// Adds a waker building chained list of them.
    pub fn add(&mut self, w: &Waker) {
        match self.waker {
            None => self.register(w),
            Some(ref mut waker) => {
                let mut waker = &mut waker.next;
                loop {
                    waker = match waker {
                        Some(w2) => &mut w2.next,
                        None => {
                            waker.replace(Box::new(
                                WakerNext {
                                    waker: w.clone(),
                                    next: None
                                }
                            ));
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Wake one registered waker, if any.
    pub fn wake_one(&mut self) {
        self.waker.take().map(|w| {
            w.waker.wake();
            w.next.map(|w2| self.waker.replace(*w2))
        });
    }

    /// Wake all registered wakers, if any.
    pub fn wake_all(&mut self) {
        while let Some(w) = self.waker.take() {
            w.waker.wake();
            w.next.map(|w| self.waker.replace(*w));
        }
    }
}
