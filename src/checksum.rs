//! checksums related functions module
//! This module is dedicated to internet checksums functions.
//!
//! credit for rfc1071, propagate_carries and one_complement_sum
//! calculation to ref. impl. <https://github.com/m-labs/smoltcp/blob/master/src/wire/ip.rs>
//! and rust's rVVRP github
use byteorder::{ByteOrder, NetworkEndian};
const _RFC1071_CHUNK_SIZE: usize = 32;

// rfc1071() function
/// compute rfc1071 internet checksum
/// returns all-ones if carried checksum is valid
#[allow(dead_code)]
pub(crate) fn confirm_checksum(mut data: &[u8]) -> u16 {
    let mut acc = 0;

    // for each 32 bytes chunk
    while data.len() >= _RFC1071_CHUNK_SIZE {
        let mut d = &data[.._RFC1071_CHUNK_SIZE];
        while d.len() >= 2 {
            // sum adjacent pairs converted to 16 bits integer
            acc += NetworkEndian::read_u16(d) as u32;
            // take the next 2 bytes for the next iteration
            d = &d[2..];
        }
        data = &data[_RFC1071_CHUNK_SIZE..];
    }

    // if it does not fit a 32 bytes chunk
    while data.len() >= 2 {
        acc += NetworkEndian::read_u16(data) as u32;
        data = &data[2..];
    }

    // add odd byte is present
    if let Some(&v) = data.first() {
        acc += (v as u32) << 8;
    }

    propagate_carries(acc)
}

#[allow(dead_code)]
// propagate final complement?
fn propagate_carries(word: u32) -> u16 {
    let sum = (word >> 16) + (word & 0xffff);
    ((sum >> 16) as u16) + (sum as u16)
}

pub fn calculate(data: &[u8], checksum_position: usize) -> u16 {
    let mut result: u16 = 0;

    // since data is in u8's, we need pairs of the data to get u16
    for (i, pair) in data.chunks(2).enumerate() {
        // the fifth pair is the checksum field, which is ignored
        if i == checksum_position {
            continue;
        }

        result = ones_complement(result, ((pair[0] as u16) << 8) | pair[1] as u16);
    }

    // do a one's complement to get the sum
    !result
}

fn ones_complement(mut first: u16, mut second: u16) -> u16 {
    let mut carry: u32 = 10;
    let mut result: u16 = 0;

    while carry != 0 {
        let tmp_res = first as u32 + second as u32;
        result = (tmp_res & 0xFFFF) as u16;
        carry = tmp_res >> 16;
        first = result;
        second = carry as u16;
    }
    result
}
