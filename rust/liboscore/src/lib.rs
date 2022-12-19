// We need these linked in
extern crate liboscore_cryptobackend;
extern crate liboscore_msgbackend;

// FIXME: pub only for tests?
pub mod raw;

mod impl_message;
pub use impl_message::ProtectedMessage;

mod oscore_option;
pub use oscore_option::OscoreOption;

mod algorithms;
pub use algorithms::{AlgorithmNotSupported, HkdfAlg, AeadAlg};

mod primitive;
pub use primitive::{PrimitiveContext, PrimitiveImmutables};
