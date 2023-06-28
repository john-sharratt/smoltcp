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
    clear_on_wake: bool,
}
impl Drop for WakerRegistration {
    fn drop(&mut self) {
        self.wake_all_and_clear()
    }
}

impl WakerRegistration {
    pub const fn new() -> Self {
        Self { waker: None, clear_on_wake: true }
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
            None => self.register(w),
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
    }

    /// Determines if the wakers will be cleared
    /// when they are triggerd (this is the default behavior)
    pub fn set_clear_on_wake(&mut self, clear_on_wake: bool) {
        self.clear_on_wake = clear_on_wake;
    }

    /// Wake all registered wakers, if any.
    pub fn wake_all(&mut self) {
        if self.clear_on_wake {
            self.wake_all_and_clear();
        } else {
            self.wake_all_by_ref();
        }
    }

    /// Wake all registered wakers, if any.
    pub fn wake_all_and_clear(&mut self) {
        if let Some(mut w) = self.waker.take() {
            w.waker.wake_by_ref();
            let mut waker = w.next.take();
            while let Some(mut w) = waker {
                w.waker.wake_by_ref();
                waker = w.next.take();
            }
        }
    }

    /// Wake all registered wakers without removing them, if any.
    pub fn wake_all_by_ref(&self) {
        if let Some(w) = self.waker.as_ref() {
            w.waker.wake_by_ref();
            let mut waker = w.next.as_ref();
            while let Some(w) = waker {
                w.waker.wake_by_ref();
                waker = w.next.as_ref();
            }
        }
    }

    /// Clears all registered wakers without waking them
    pub fn clear(&mut self) {
        self.waker.take();
    }
}
