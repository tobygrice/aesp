mod ecb;
mod ctr;
mod gcm;
mod util;


pub use ctr::{ctr_core_serial, ctr_core_parallel};
pub use ecb::{ecb_core_enc_serial, ecb_core_dec_serial};
pub use gcm::compute_tag;