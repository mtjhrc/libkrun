pub mod api;
mod attach;
pub use api::*;

ffier::generate_bridge!(
    local = __ffier_krun_metadata,
    schema_output = "../../target/ffier-krun.json"
);

#[doc(hidden)]
pub mod reexports {
    pub use ::devices::virtio::TsiFlags;
    #[cfg(feature = "net")]
    pub use ::devices::virtio::net::device::VirtioNetBackend;
    pub use ::devices::virtio::port_io;
}
