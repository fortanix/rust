use enclave_runner_client::{Client, Error};

use crate::ops::{Deref, DerefMut};

pub(crate) struct ClientRunner {
    inner: Client,
}

impl ClientRunner {
    pub fn new() -> Result<Self, Error> {
        Ok(ClientRunner { inner: Client::new(None)? })
    }

    pub fn args(port: Option<u32>) -> Result<Vec<String>, Error> {
        Client::args(None)
    }

    pub fn exit(port: Option<u32>, code: i32) -> ! {
        Client::exit(None, code)
    }
}

impl Deref for ClientRunner {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.inner
    }
}

impl DerefMut for ClientRunner {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.inner
    }
}