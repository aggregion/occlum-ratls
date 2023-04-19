use std::sync::Arc;

mod occlum;

pub trait DcapBuilder: Send + Sync {
    fn build() -> Vec<u8>;
}

// pub fn get_dcap_builder() -> Arc<dyn DcapBuilder> {}