pub mod converter;
pub mod network;
pub mod base_functions;
pub mod config;

mod router;
mod state_machine;
mod pkt;


pub mod error{
    use std::fmt::Display;

    #[derive(Debug)]
    pub struct NetError(pub String);
    
    impl Display for NetError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    #[derive(Debug)]
    pub struct OptError(pub String);

    impl Display for OptError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
}