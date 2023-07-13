pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[typetag::serde]
pub trait Protocol {
    fn advance(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn finish(self: Box<Self>) -> Result<Vec<u8>>;
}

#[typetag::serde]
pub trait KeygenProtocol: Protocol {
    fn new() -> Self
    where
        Self: Sized;
}
