extern crate occlum_dcap;

use std::io::Result;
use log::trace;
use occlum_dcap::{
    DcapQuote,
    sgx_report_data_t,
    sgx_ql_qv_result_t,
    IoctlVerDCAPQuoteArg,
    sgx_report_body_t,
    sgx_quote_header_t,
};

pub struct OcclumDcapBuilder {
    dcap_quote: DcapQuote,
    quote_size: u32,
    quote_buf: Vec<u8>,
    req_data: sgx_report_data_t,
    supplemental_size: u32,
    suppl_buf: Vec<u8>,
}

impl OcclumDcapBuilder {
    pub fn new(report_data: &str) -> Self {
        let mut dcap = DcapQuote::new();
        let quote_size = dcap.get_quote_size();
        let supplemental_size = dcap.get_supplemental_data_size();
        let quote_buf: Vec<u8> = vec![0; quote_size as usize];
        let suppl_buf: Vec<u8> = vec![0; supplemental_size as usize];

        let mut req_data = sgx_report_data_t::default();

        //fill in the report data array
        for (pos, val) in report_data.as_bytes().iter().enumerate() {
            req_data.d[pos] = *val;
        }

        Self {
            dcap_quote: dcap,
            quote_size: quote_size,
            quote_buf: quote_buf,
            req_data: req_data,
            supplemental_size: supplemental_size,
            suppl_buf: suppl_buf,
        }
    }

    fn dcap_quote_gen(&mut self) {
        self.dcap_quote.generate_quote(self.quote_buf.as_mut_ptr(), &mut self.req_data).unwrap();
    }

    fn dcap_quote_get_report_body(&mut self) -> Result<*const sgx_report_body_t> {
        let report_body_offset = std::mem::size_of::<sgx_quote_header_t>();
        let report_body: *const sgx_report_body_t = self.quote_buf[
            report_body_offset..
        ].as_ptr() as _;

        Ok(report_body)
    }

    fn dcap_quote_get_report_data(&mut self) -> Result<*const sgx_report_data_t> {
        let report_body_ptr = self.dcap_quote_get_report_body().unwrap();
        let report_data_ptr = unsafe { &(*report_body_ptr).report_data };

        Ok(report_data_ptr)
    }

    fn dcap_quote_ver(&mut self) -> Result<sgx_ql_qv_result_t> {
        let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
        let mut status = 1;

        let mut verify_arg = IoctlVerDCAPQuoteArg {
            quote_buf: self.quote_buf.as_mut_ptr(),
            quote_size: self.quote_size,
            collateral_expiration_status: &mut status,
            quote_verification_result: &mut quote_verification_result,
            supplemental_data_size: self.supplemental_size,
            supplemental_data: self.suppl_buf.as_mut_ptr(),
        };

        self.dcap_quote.verify_quote(&mut verify_arg).unwrap();
        println!("DCAP verify quote successfully");

        Ok(quote_verification_result)
    }

    fn dcap_dump_quote_info(&mut self) {
        let report_body_ptr = self.dcap_quote_get_report_body().unwrap();

        // Dump ISV FAMILY ID
        let family_id = unsafe { (*report_body_ptr).isv_family_id };
        let (fam_id_l, fam_id_h) = family_id.split_at(8);
        let fam_id_l = <&[u8; 8]>::try_from(fam_id_l).unwrap();
        let fam_id_l = u64::from_le_bytes(*fam_id_l);
        let fam_id_h = <&[u8; 8]>::try_from(fam_id_h).unwrap();
        let fam_id_h = u64::from_le_bytes(*fam_id_h);
        println!("\nSGX ISV Family ID:");
        println!("\t Low 8 bytes: 0x{:016x?}\t", fam_id_l);
        println!("\t high 8 bytes: 0x{:016x?}\t", fam_id_h);

        // println!("MRSIGNER: {:?}", unsafe { (*report_body_ptr).mr_signer });

        // Dump ISV EXT Product ID
        let prod_id = unsafe { (*report_body_ptr).isv_ext_prod_id };
        let (prod_id_l, prod_id_h) = prod_id.split_at(8);
        let prod_id_l = <&[u8; 8]>::try_from(prod_id_l).unwrap();
        let prod_id_l = u64::from_le_bytes(*prod_id_l);
        let prod_id_h = <&[u8; 8]>::try_from(prod_id_h).unwrap();
        let prod_id_h = u64::from_le_bytes(*prod_id_h);
        println!("\nSGX ISV EXT Product ID:");
        println!("\t Low 8 bytes: 0x{:016x?}\t", prod_id_l);
        println!("\t high 8 bytes: 0x{:016x?}\t", prod_id_h);

        // Dump CONFIG ID
        let conf_id = unsafe { (*report_body_ptr).config_id };
        println!("\nSGX CONFIG ID:");
        println!("\t{:02x?}", &conf_id[..16]);
        println!("\t{:02x?}", &conf_id[16..32]);
        println!("\t{:02x?}", &conf_id[32..48]);
        println!("\t{:02x?}", &conf_id[48..]);

        // Dump CONFIG SVN
        let conf_svn = unsafe { (*report_body_ptr).config_svn };
        println!("\nSGX CONFIG SVN:\t {:04x?}", conf_svn);
    }
}