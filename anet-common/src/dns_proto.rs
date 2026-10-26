use std::ops::Range;

pub const DNS_QTYPE_TXT: u16 = 16;
pub const DNS_QCLASS_IN: u16 = 1;
pub const EDNS0_UDP_SIZE: u16 = 1232;

#[derive(Debug, Clone)]
pub struct ParsedDnsQuery {
    pub tx_id: u16,
    pub flags: u16,
    pub qname: String,
    pub raw_qname_range: Range<usize>,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end: usize,
}

/// Parses a binary DNS query packet according to RFC 1035.
pub fn parse_dns_query(data: &[u8]) -> Option<ParsedDnsQuery> {
    if data.len() < 12 {
        return None;
    }

    let tx_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);

    if qdcount == 0 {
        return None;
    }

    let qname_start = 12;
    let mut pos = qname_start;
    let mut labels = Vec::new();

    while pos < data.len() {
        let len = data[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if (len & 0xC0) != 0 {
            // Compressed pointer in question is non-standard
            return None;
        }
        if pos + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[pos..pos + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
    }

    let qname_end = pos;
    if pos + 4 > data.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let question_end = pos + 4;

    Some(ParsedDnsQuery {
        tx_id,
        flags,
        qname: labels.join("."),
        raw_qname_range: qname_start..qname_end,
        qtype,
        qclass,
        question_end,
    })
}

/// Constructs a binary DoH query for a TXT record with EDNS0 (1232B UDP payload size).
pub fn build_doh_query(qname: &str, tx_id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(qname.len() + 32);

    // Header (12 bytes)
    buf.extend_from_slice(&tx_id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    buf.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT=1 (EDNS0)

    // Question Section
    for label in qname.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        buf.push(bytes.len().min(63) as u8);
        buf.extend_from_slice(&bytes[..bytes.len().min(63)]);
    }
    buf.push(0x00); // Root label

    buf.extend_from_slice(&DNS_QTYPE_TXT.to_be_bytes());
    buf.extend_from_slice(&DNS_QCLASS_IN.to_be_bytes());

    // Additional Section: EDNS0 OPT RR (RFC 6891)
    buf.push(0x00); // Root name
    buf.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT (41)
    buf.extend_from_slice(&EDNS0_UDP_SIZE.to_be_bytes()); // UDP payload size = 1232
    buf.extend_from_slice(&0u32.to_be_bytes()); // Extended RCODE and flags
    buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

    buf
}

/// Constructs a DNS response with a TXT record, echoing Question section exactly (0x20 bit compliant).
pub fn build_dns_txt_response(
    orig_query: &[u8],
    parsed_q: &ParsedDnsQuery,
    txt_payload: Option<&[u8]>,
    ttl: u32,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(512);

    let rr_slices: Vec<&[u8]> = match txt_payload {
        Some(p) if !p.is_empty() => p.chunks(765).collect(),
        Some(_) => vec![&[][..]],
        None => Vec::new(),
    };
    let ancount = rr_slices.len() as u16;

    // 1. Header (12 bytes)
    resp.extend_from_slice(&parsed_q.tx_id.to_be_bytes());
    // Flags: QR=1 (response), AA=1 (authoritative), RD=preserved, RA=1, RCODE=0 (NoError)
    let rd_bit = parsed_q.flags & 0x0100;
    let resp_flags = 0x8400 | rd_bit;
    resp.extend_from_slice(&resp_flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT (Multi-TXT support)
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT=1 (EDNS0)

    // 2. Question section (copied verbatim from orig_query to preserve 0x20 casing)
    if parsed_q.question_end <= orig_query.len() {
        resp.extend_from_slice(&orig_query[12..parsed_q.question_end]);
    } else {
        // Fallback
        for label in parsed_q.qname.split('.') {
            if !label.is_empty() {
                resp.push(label.len() as u8);
                resp.extend_from_slice(label.as_bytes());
            }
        }
        resp.push(0x00);
        resp.extend_from_slice(&DNS_QTYPE_TXT.to_be_bytes());
        resp.extend_from_slice(&DNS_QCLASS_IN.to_be_bytes());
    }

    // 3. Answer section (1 or more TXT Resource Records with 0xC00C name compression)
    for payload in rr_slices {
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&DNS_QTYPE_TXT.to_be_bytes());
        resp.extend_from_slice(&DNS_QCLASS_IN.to_be_bytes());
        resp.extend_from_slice(&ttl.to_be_bytes());

        let mut rdlength = 0usize;
        if payload.is_empty() {
            rdlength = 1;
        } else {
            for chunk in payload.chunks(255) {
                rdlength += 1 + chunk.len();
            }
        }

        resp.extend_from_slice(&(rdlength as u16).to_be_bytes());

        if payload.is_empty() {
            resp.push(0x00);
        } else {
            for chunk in payload.chunks(255) {
                resp.push(chunk.len() as u8);
                resp.extend_from_slice(chunk);
            }
        }
    }

    // 4. Additional section: EDNS0 OPT RR (RFC 6891)
    resp.push(0x00); // Root name
    resp.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT (41)
    resp.extend_from_slice(&EDNS0_UDP_SIZE.to_be_bytes()); // UDP payload size = 1232
    resp.extend_from_slice(&0u32.to_be_bytes()); // Extended RCODE and flags
    resp.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

    resp
}

/// Parses a binary DNS response and extracts concatenated TXT character-strings across all TXT Resource Records.
pub fn parse_dns_txt_response(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return None; // Non-zero RCODE
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if ancount == 0 {
        return None; // No answers (NODATA)
    }

    let mut pos = 12;

    // Skip question section(s)
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        if pos + 4 > data.len() {
            return None;
        }
        pos += 4; // QTYPE (2) + QCLASS (2)
    }

    let mut combined_txt = Vec::new();
    let mut found_txt = false;

    // Parse Answer section concatenating all TXT (type 16) Resource Records
    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;
        if pos + 10 > data.len() {
            return None;
        }

        let atype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            return None;
        }

        if atype == DNS_QTYPE_TXT {
            found_txt = true;
            let rdata = &data[pos..pos + rdlength];
            let mut sub_pos = 0;
            while sub_pos < rdata.len() {
                let slen = rdata[sub_pos] as usize;
                sub_pos += 1;
                if sub_pos + slen > rdata.len() {
                    break;
                }
                combined_txt.extend_from_slice(&rdata[sub_pos..sub_pos + slen]);
                sub_pos += slen;
            }
        }

        pos += rdlength;
    }

    if found_txt {
        Some(combined_txt)
    } else {
        None
    }
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    while pos < buf.len() {
        let b = buf[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if (b & 0xC0) == 0xC0 {
            if pos + 2 > buf.len() {
                return None;
            }
            return Some(pos + 2);
        }
        let len = b as usize;
        pos += 1 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_query_and_response_roundtrip() {
        let qname = "poll.1234abcd.beef01.t1.anet-vpn.com";
        let query_bytes = build_doh_query(qname, 0x1337);

        let parsed = parse_dns_query(&query_bytes).expect("Query parsing failed");
        assert_eq!(parsed.tx_id, 0x1337);
        assert_eq!(parsed.qname, qname);
        assert_eq!(parsed.qtype, DNS_QTYPE_TXT);

        let mock_txt_data = b"SGVsbG8gV29ybGQgZnJvbSBBTmV0IERvSCBUdW5uZWwh";
        let resp_bytes = build_dns_txt_response(&query_bytes, &parsed, Some(mock_txt_data), 0);

        let extracted = parse_dns_txt_response(&resp_bytes).expect("Response parsing failed");
        assert_eq!(extracted, mock_txt_data);
    }
}
