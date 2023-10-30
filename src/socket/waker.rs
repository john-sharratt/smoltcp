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
    wake_on_add: bool,
}

impl WakerRegistration {
    pub const fn new() -> Self {
        Self {
            waker: None,
            wake_on_add: false,
        }
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
            _ => {
                self.waker = Some(WakerNext {
                    waker: w.clone(),
                    next: None,
                })
            }
        }
    }

    /// Adds a waker building chained list of them.
    pub fn add(&mut self, w: &Waker) {
        match self.waker {
            None => {
                self.register(w);
            }
            Some(ref mut waker) => {
                if waker.waker.will_wake(w) {
                    return;
                }
                let mut waker = &mut waker.next;
                loop {
                    waker = match waker {
                        Some(w2) if w2.waker.will_wake(w) => {
                            return;
                        }
                        Some(w2) => &mut w2.next,
                        None => {
                            waker.replace(Box::new(WakerNext {
                                waker: w.clone(),
                                next: None,
                            }));
                            return;
                        }
                    }
                }
            }
        }
        if self.wake_on_add {
            self.wake_on_add = false;
            self.wake_all_internal();
        }
    }

    /// Wake all registered wakers, if any.
    fn wake_all_internal(&mut self) {
        if let Some(mut w) = self.waker.take() {
            w.waker.wake_by_ref();
            let mut waker = w.next.take();
            while let Some(mut w) = waker {
                w.waker.wake_by_ref();
                waker = w.next.take();
            }
        }
    }

    /// Wake all registered wakers, if any.
    pub fn wake_all(&mut self) {
        if self.waker.is_some() {
            self.wake_all_internal();
        } else {
            self.wake_on_add = true;
        }
    }

    /// Clears all registered wakers without waking them
    pub fn clear(&mut self) {
        self.wake_on_add = false;
        self.waker.take();
    }
}
