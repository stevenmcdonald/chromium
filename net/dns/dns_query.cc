// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_query.h"

#include <utility>

#include "base/big_endian.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/numerics/safe_conversions.h"
#include "base/sys_byteorder.h"
#include "net/base/io_buffer.h"
#include "net/dns/dns_util.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/record_rdata.h"
#include "third_party/abseil-cpp/absl/types/optional.h"

namespace net {

namespace {

const size_t kHeaderSize = sizeof(dns_protocol::Header);

// Size of the fixed part of an OPT RR:
// https://tools.ietf.org/html/rfc6891#section-6.1.2
static const size_t kOptRRFixedSize = 11;

// https://tools.ietf.org/html/rfc6891#section-6.2.5
// TODO(robpercival): Determine a good value for this programmatically.
const uint16_t kMaxUdpPayloadSize = 4096;

size_t QuestionSize(size_t qname_size) {
  // QNAME + QTYPE + QCLASS
  return qname_size + sizeof(uint16_t) + sizeof(uint16_t);
}

// Buffer size of Opt record for |rdata| (does not include Opt record or RData
// added for padding).
size_t OptRecordSize(const OptRecordRdata* rdata) {
  return rdata == nullptr ? 0 : kOptRRFixedSize + rdata->buf().size();
}

// Padding size includes Opt header for the padding.  Does not include OptRecord
// header (kOptRRFixedSize) even when added just for padding.
size_t DeterminePaddingSize(size_t unpadded_size,
                            DnsQuery::PaddingStrategy padding_strategy) {
  switch (padding_strategy) {
    case DnsQuery::PaddingStrategy::NONE:
      return 0;
    case DnsQuery::PaddingStrategy::BLOCK_LENGTH_128:
      size_t padding_size = OptRecordRdata::Opt::kHeaderSize;
      size_t remainder = (padding_size + unpadded_size) % 128;
      padding_size += (128 - remainder) % 128;
      DCHECK_EQ((unpadded_size + padding_size) % 128, 0u);
      return padding_size;
  }
}

absl::optional<OptRecordRdata> AddPaddingIfNecessary(
    const OptRecordRdata* opt_rdata,
    DnsQuery::PaddingStrategy padding_strategy,
    size_t no_opt_buffer_size) {

  VLOG(1) << "[breakerspace] AddPaddingIfNecessary()";
  // If no input OPT record rdata and no padding, no OPT record rdata needed.
  if (!opt_rdata && padding_strategy == DnsQuery::PaddingStrategy::NONE)
    return absl::nullopt;

  OptRecordRdata merged_opt_rdata;
  if (opt_rdata)
    merged_opt_rdata.AddOpts(*opt_rdata);

  size_t unpadded_size = no_opt_buffer_size + OptRecordSize(&merged_opt_rdata);
  size_t padding_size = DeterminePaddingSize(unpadded_size, padding_strategy);

  if (padding_size > 0) {
    // |opt_rdata| must not already contain padding if DnsQuery is to add
    // padding.
    DCHECK(!merged_opt_rdata.ContainsOptCode(dns_protocol::kEdnsPadding));
    // OPT header is the minimum amount of padding.
    DCHECK(padding_size >= OptRecordRdata::Opt::kHeaderSize);

    merged_opt_rdata.AddOpt(OptRecordRdata::Opt(
        dns_protocol::kEdnsPadding,
        std::string(padding_size - OptRecordRdata::Opt::kHeaderSize, 0)));
  }

  return merged_opt_rdata;
}

}  // namespace


void DnsQuery::AddPadding(absl::optional<OptRecordRdata>* merged_opt_rdata, base::BigEndianWriter* writer) {
  if (*merged_opt_rdata) {

    VLOG(1) << "[breakerspace] merged_opt_rdata";
    DCHECK(!merged_opt_rdata->value().opts().empty());

    header_->arcount = base::HostToNet16(1);
    // Write OPT pseudo-resource record.
    writer->WriteU8(0);                       // empty domain name (root domain)
    writer->WriteU16(OptRecordRdata::kType);  // type
    writer->WriteU16(kMaxUdpPayloadSize);     // class
    // ttl (next 3 fields)
    writer->WriteU8(0);  // rcode does not apply to requests
    writer->WriteU8(0);  // version
    // TODO(robpercival): Set "DNSSEC OK" flag if/when DNSSEC is supported:
    // https://tools.ietf.org/html/rfc3225#section-3
    writer->WriteU16(0);  // flags

    // rdata
    writer->WriteU16(merged_opt_rdata->value().buf().size());  // rdata length
    writer->WriteBytes(merged_opt_rdata->value().buf().data(),
                      merged_opt_rdata->value().buf().size());
  }

}

//Creates an IOBuffer with the appropriate size and gives its header the default settings (RD flag set and qdcount 1)
void DnsQuery::CreateIOBufferAndHeader(uint16_t id, const base::StringPiece& qname, uint16_t qtype, size_t size) {
	size_t buffer_size = size;

	io_buffer_ = base::MakeRefCounted<IOBufferWithSize>(buffer_size);

	header_ = reinterpret_cast<dns_protocol::Header*>(io_buffer_->data());
  	*header_ = {};
  	header_->id = base::HostToNet16(id);

	header_->flags = base::HostToNet16(dns_protocol::kFlagRD);

	header_->qdcount = base::HostToNet16(1);
}

void DnsQuery::UnmodifiedStrategy(uint16_t id, const base::StringPiece& qname, uint16_t qtype,
                const OptRecordRdata* opt_rdata, PaddingStrategy padding_strategy) {

	size_t buffer_size = kHeaderSize + QuestionSize(qname.size());

        qname_size_ = qname.size();

        absl::optional<OptRecordRdata> merged_opt_rdata = AddPaddingIfNecessary(opt_rdata, padding_strategy, buffer_size);

        if (merged_opt_rdata)
                buffer_size += OptRecordSize(&merged_opt_rdata.value());

        CreateIOBufferAndHeader(id, qname, qtype, buffer_size);

        //Write a question record
        base::BigEndianWriter writer(io_buffer_->data() + kHeaderSize,
                               io_buffer_->size() - kHeaderSize);
        writer.WriteBytes(qname.data(), qname.size());
        writer.WriteU16(qtype);
        writer.WriteU16(dns_protocol::kClassIN);

        if (merged_opt_rdata) {
           AddPadding(&merged_opt_rdata, &writer);
        }
}
void DnsQuery::ElevatedCountStrategy(uint16_t id, const base::StringPiece& qname, uint16_t qtype,
		const OptRecordRdata* opt_rdata, PaddingStrategy padding_strategy) {
	

	size_t buffer_size = kHeaderSize + QuestionSize(qname.size());
	
	qname_size_ = qname.size();
	
	absl::optional<OptRecordRdata> merged_opt_rdata = AddPaddingIfNecessary(opt_rdata, padding_strategy, buffer_size);
  	
	if (merged_opt_rdata)
    		buffer_size += OptRecordSize(&merged_opt_rdata.value());
	
	CreateIOBufferAndHeader(id, qname, qtype, buffer_size);

	//Set qdcount to 2	
	header_->qdcount = base::HostToNet16(2);

	//Write a question record
	base::BigEndianWriter writer(io_buffer_->data() + kHeaderSize,
                               io_buffer_->size() - kHeaderSize);
	writer.WriteBytes(qname.data(), qname.size());
	writer.WriteU16(qtype);
	writer.WriteU16(dns_protocol::kClassIN);

	if (merged_opt_rdata) {
	   AddPadding(&merged_opt_rdata, &writer);
	}
}

void DnsQuery::TruncatedReservedStrategy(uint16_t id, const base::StringPiece& qname, uint16_t qtype,
                const OptRecordRdata* opt_rdata, PaddingStrategy padding_strategy) {


        size_t buffer_size = kHeaderSize + QuestionSize(qname.size());

        qname_size_ = qname.size();

        absl::optional<OptRecordRdata> merged_opt_rdata = AddPaddingIfNecessary(opt_rdata, padding_strategy, buffer_size);

        if (merged_opt_rdata)
                buffer_size += OptRecordSize(&merged_opt_rdata.value());

        CreateIOBufferAndHeader(id, qname, qtype, buffer_size);

	//Setting tc and z flags
        uint16_t new_flags = dns_protocol::kFlagRD;
  	//0x40 = 0b1000000, setting z to 1.
  	new_flags |= 0x40;
  	//setting tc to 1
  	new_flags |= dns_protocol::kFlagTC;
  	//changing header_ flag field
  	header_->flags = base::HostToNet16(new_flags);

	//changing nscount
	header_->nscount = base::HostToNet16(1);

	//writing a question record
        base::BigEndianWriter writer(io_buffer_->data() + kHeaderSize,
                               io_buffer_->size() - kHeaderSize);
        writer.WriteBytes(qname.data(), qname.size());
        writer.WriteU16(qtype);
        writer.WriteU16(dns_protocol::kClassIN);

        if (merged_opt_rdata) {
           AddPadding(&merged_opt_rdata, &writer);
        }
}

void DnsQuery::MultiByteStrategy(uint16_t id, const base::StringPiece& qname, uint16_t qtype,
                const OptRecordRdata* opt_rdata, PaddingStrategy padding_strategy) {

	size_t buffer_size = kHeaderSize + QuestionSize(qname.size());

        qname_size_ = qname.size();

	//increase buffer size by 721 2-byte characters
        buffer_size += QuestionSize(721 * 2 + 1);
	
	absl::optional<OptRecordRdata> merged_opt_rdata = AddPaddingIfNecessary(opt_rdata, padding_strategy, buffer_size);

        if (merged_opt_rdata)
                buffer_size += OptRecordSize(&merged_opt_rdata.value());

        CreateIOBufferAndHeader(id, qname, qtype, buffer_size);

        //write first question record
        base::BigEndianWriter writer(io_buffer_->data() + kHeaderSize,
                               io_buffer_->size() - kHeaderSize);
        writer.WriteBytes(qname.data(), qname.size());
        writer.WriteU16(qtype);
        writer.WriteU16(dns_protocol::kClassIN);

	unsigned char multibyte_data[721 * 2 + 1];

	for(int i = 0; i < 721 * 2; i+=2){
      		multibyte_data[i] = 0xc2;
      		multibyte_data[i + 1] = 0xa4;
  	}

	multibyte_data[721 * 2] = 0;

	//write multibyte characters to a new question record
  	writer.WriteBytes(multibyte_data, 721 * 2 + 1);
	writer.WriteU16(qtype);
  	writer.WriteU16(dns_protocol::kClassIN);

        if (merged_opt_rdata) {
           AddPadding(&merged_opt_rdata, &writer);
        }

}

void DnsQuery::MultiByteStrategyElevatedCount(uint16_t id, const base::StringPiece& qname, uint16_t qtype,
                const OptRecordRdata* opt_rdata, PaddingStrategy padding_strategy) {
	
	MultiByteStrategy(id, qname, qtype, opt_rdata, padding_strategy);

	header_->arcount = base::HostToNet16(1);

}

void DnsQuery::CompressedStrategy(uint16_t id, const base::StringPiece& qname, uint16_t qtype,
                const OptRecordRdata* opt_rdata, PaddingStrategy padding_strategy) {

	size_t buffer_size = kHeaderSize;

        qname_size_ = qname.size();


	size_t uncompressed_buffer_size = kHeaderSize + QuestionSize(qname_size_);
	compressed = true;
	io_buffer_uncompressed = base::MakeRefCounted<IOBufferWithSize>(uncompressed_buffer_size);
	
	//The qname is divided into sections, the first section's length is the 0th element of qname
	size_t first_section_length = qname.data()[0];
	//The first question record will have first_section_length characters + the length octet +
	//the number indicating a pointer + the offset
	buffer_size += QuestionSize(first_section_length + 3);

	VLOG(1) << "[breakerspace] first section length: " << first_section_length;
	size_t rest_of_length = qname_size_ - (first_section_length + 1);
	buffer_size += QuestionSize(rest_of_length);


        absl::optional<OptRecordRdata> merged_opt_rdata = AddPaddingIfNecessary(opt_rdata, padding_strategy, buffer_size);
        if (merged_opt_rdata)
                buffer_size += OptRecordSize(&merged_opt_rdata.value());

        CreateIOBufferAndHeader(id, qname, qtype, buffer_size);

        
	unsigned char* first_section = new unsigned char[first_section_length + 3];
	first_section[0] = first_section_length;
	if ((12 + (first_section_length + 3) + 4) > 255) {
		first_section[first_section_length + 1] = 0xc0 | ((12 + (first_section_length + 3) + 4) >> 8);
		first_section[first_section_length + 2] = ((12 + (first_section_length + 3) + 4)) & 0xff; 
	} else {

		first_section[first_section_length + 1] = 192;
		first_section[first_section_length + 2] = 12 + (first_section_length + 3) + 4;
	}
	for (size_t i = 1; i <= first_section_length; i++) {
		first_section[i] = qname.data()[i];
	}



	base::BigEndianWriter writer(io_buffer_->data() + kHeaderSize,
                               io_buffer_->size() - kHeaderSize);

        writer.WriteBytes(first_section, first_section_length + 3);
  	writer.WriteU16(qtype);
  	writer.WriteU16(dns_protocol::kClassIN);


  	writer.WriteBytes(&(qname.data()[first_section_length + 1]), rest_of_length);
  	writer.WriteU16(qtype);
  	writer.WriteU16(dns_protocol::kClassIN);

	header_->qdcount = base::HostToNet16(2);



  	dns_protocol::Header* header_uncompressed;
     	header_uncompressed = reinterpret_cast<dns_protocol::Header*>(io_buffer_uncompressed->data());
     	*header_uncompressed = {};
     	header_uncompressed->id = base::HostToNet16(id);
     	header_->flags = base::HostToNet16(dns_protocol::kFlagRD);
     	header_uncompressed->qdcount = base::HostToNet16(2);

     	VLOG(1) << "[breakerspace] qname.data() = " << qname.data();
     	base::BigEndianWriter uncompressed_writer(io_buffer_uncompressed->data() + kHeaderSize,
                                                io_buffer_uncompressed->size() - kHeaderSize);
     	uncompressed_writer.WriteBytes(qname.data(), qname.size());
     	uncompressed_writer.WriteU16(qtype);
     	uncompressed_writer.WriteU16(dns_protocol::kClassIN);

        if (merged_opt_rdata) {
           AddPadding(&merged_opt_rdata, &writer);
        }

}

// DNS query consists of a 12-byte header followed by a question section.
// For details, see RFC 1035 section 4.1.1.  This header template sets RD
// bit, which directs the name server to pursue query recursively, and sets
// the QDCOUNT to 1, meaning the question section has a single entry.

DnsQuery::DnsQuery(uint16_t id,
                   const base::StringPiece& qname,
                   uint16_t qtype,
                   const OptRecordRdata* opt_rdata,
                   PaddingStrategy padding_strategy,
		   unsigned int packet_strategy)
    : qname_size_(qname.size()), strategy(packet_strategy) {
#if DCHECK_IS_ON()
  absl::optional<std::string> dotted_name = DnsDomainToString(qname);
  DCHECK(dotted_name && !dotted_name.value().empty());
#endif  // DCHECK_IS_ON()

  VLOG(1) << "[breakerspace] DnsQuery::DnsQuery()";
  
  switch (strategy) {
	case 1:
		ElevatedCountStrategy(id, qname, qtype, opt_rdata, padding_strategy);
		break;
	case 2:
		TruncatedReservedStrategy(id, qname, qtype, opt_rdata, padding_strategy);
		break;
	case 3:
		MultiByteStrategy(id, qname, qtype, opt_rdata, padding_strategy);
		break;
	case 4:
		MultiByteStrategyElevatedCount(id, qname, qtype, opt_rdata, padding_strategy);
		break;
	case 5:
		CompressedStrategy(id, qname, qtype, opt_rdata, padding_strategy);
		break;
	default:
		UnmodifiedStrategy(id, qname, qtype, opt_rdata, padding_strategy);
  }

  //CompressedStrategy(id, qname, qtype, opt_rdata, padding_strategy);
  //MultiByteStrategyElevatedCount(id, qname, qtype, opt_rdata, padding_strategy);
  //MultiByteStrategy(id, qname, qtype, opt_rdata, padding_strategy);
  //TruncatedReservedStrategy(id, qname, qtype, opt_rdata, padding_strategy);
  //ElevatedCountStrategy(id, qname, qtype, opt_rdata, padding_strategy);
  
  /*
  size_t buffer_size = 0;
  int strategy = 1;

  if (strategy == 1)   void ElevatedCountStrategy(uint16_t id, const base::StringPiece& qname, uint16_t qtype, const OptRecordRdata* opt_rdata = nullptr,
           PaddingStrategy padding_strategy = PaddingStrategy::NONE);{
	
  }

  absl::optional<OptRecordRdata> merged_opt_rdata =
      AddPaddingIfNecessary(opt_rdata, padding_strategy, buffer_size);
  if (merged_opt_rdata)
    buffer_size += OptRecordSize(&merged_opt_rdata.value());

  */
  /*

  // original
  //size_t buffer_size = kHeaderSize + QuestionSize(qname_size_);
  
  // Compression, make the second qr say example.com and the first have www.(pointer to example.com)
  
  size_t buffer_size = kHeaderSize + QuestionSize(6) + QuestionSize(13);
  size_t uncompressed_buffer_size = kHeaderSize + QuestionSize(qname_size_);
  compressed = true;
  

  // Long Secondary Query
  //buffer_size += QuestionSize(719 * 4 + 1);
  

  absl::optional<OptRecordRdata> merged_opt_rdata =
      AddPaddingIfNecessary(opt_rdata, padding_strategy, buffer_size);
  if (merged_opt_rdata)
    buffer_size += OptRecordSize(&merged_opt_rdata.value());

  io_buffer_ = base::MakeRefCounted<IOBufferWithSize>(buffer_size);

  //Compression
  
  if (compressed) {
     io_buffer_uncompressed = base::MakeRefCounted<IOBufferWithSize>(uncompressed_buffer_size);
  }
  
  header_ = reinterpret_cast<dns_protocol::Header*>(io_buffer_->data());
  *header_ = {};
  header_->id = base::HostToNet16(id);
  

  //Originally, RD is the only flag set, and nscount is not 1
  header_->flags = base::HostToNet16(dns_protocol::kFlagRD);
  
  
  // [breakerspace] Truncated-Reserved, set nscount, z, and tc to 1
  // For the Truncated+Reserved strategy, this could be:
  //	 ancount >= 1
  //     arcount >= 1
  //     nscount >= 1
  //     qdcount >= 2
  uint16_t new_flags = dns_protocol::kFlagRD;
  // [breakerspace] 0x40 = 0b1000000, setting z to 1.
  new_flags |= 0x40;
  // [breakerspace] setting tc to 1
  new_flags |= dns_protocol::kFlagTC;
  // [breakerspace] changing header_ flag field  
  header_->flags = base::HostToNet16(new_flags); 
  VLOG(1) << "[breakerspace] FLAGS = " << new_flags;
 

  //header_->nscount = base::HostToNet16(1);
  //header_->qdcount = base::HostToNet16(2);
  //header_->ancount = base::HostToNet16(1);
  
  */

  /*

  // Originally, the QDCount is set to 1
  //header_->qdcount = base::HostToNet16(1);

  // [breakerspace] Elevated Count, set qdcount to 2
  header_->qdcount = base::HostToNet16(2);
  
  // Write question section after the header.
  base::BigEndianWriter writer(io_buffer_->data() + kHeaderSize,
                               io_buffer_->size() - kHeaderSize);
  
  //Originally, the qname is written
  //writer.WriteBytes(qname.data(), qname.size());
  //writer.WriteU16(qtype);
  //writer.WriteU16(dns_protocol::kClassIN);

  VLOG(1) << "[breakerspace] qname.data(): " << qname.data();
  VLOG(1) << "[breakerspace] qname.data()[0]: " << int(qname.data()[0]);
  VLOG(1) << "[breakerspace] qname.data()[4]: " << int(qname.data()[4]);

  
  unsigned char example_com_arr[13] = {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
  
  unsigned char www_arr[6] = {3, 'w', 'w', 'w', 192, 22};
  
  
  writer.WriteBytes(www_arr, 6);
  writer.WriteU16(qtype);
  writer.WriteU16(dns_protocol::kClassIN);
  
  writer.WriteBytes(example_com_arr, 13);
  writer.WriteU16(qtype);
  writer.WriteU16(dns_protocol::kClassIN);
  
  
  if (compressed) {
     
     dns_protocol::Header* header_uncompressed;
     header_uncompressed = reinterpret_cast<dns_protocol::Header*>(io_buffer_uncompressed->data());
     *header_uncompressed = {};
     header_uncompressed->id = base::HostToNet16(id);
     header_->flags = base::HostToNet16(dns_protocol::kFlagRD);
     header_uncompressed->qdcount = base::HostToNet16(2);
    
     VLOG(1) << "[breakerspace] qname.data() = " << qname.data(); 
     base::BigEndianWriter uncompressed_writer(io_buffer_uncompressed->data() + kHeaderSize,
		     				io_buffer_uncompressed->size() - kHeaderSize);
     uncompressed_writer.WriteBytes(qname.data(), qname.size());
     uncompressed_writer.WriteU16(qtype);
     uncompressed_writer.WriteU16(dns_protocol::kClassIN);

  }

  

   Long Secondary Query
   unsigned char multibyte_data[719 * 2 + 1];
  //[breakerspace] Might not need to do length octet?
  //multibyte_data[0] = 1334 * 2 + 2;
  multibyte_data[719 * 2] = 0;

  //for(int i = 1; i < (1334 * 2 + 2) - 1; i+=2){
  for(int i = 0; i < 719 * 2; i+=2){
      multibyte_data[i] = 0xc2;
      multibyte_data[i + 1] = 0xa4;
  }
  writer.WriteBytes(multibyte_data, 719 * 2);
  writer.WriteBytes(multibyte_data, 719 * 2 + 1);
  
  writer.WriteU16(qtype);
  writer.WriteU16(dns_protocol::kClassIN);
  */

/*
  if (merged_opt_rdata) {
    
    VLOG(1) << "[breakerspace] merged_opt_rdata";
    DCHECK(!merged_opt_rdata.value().opts().empty());

    header_->arcount = base::HostToNet16(1);
    // Write OPT pseudo-resource record.
    writer.WriteU8(0);                       // empty domain name (root domain)
    writer.WriteU16(OptRecordRdata::kType);  // type
    writer.WriteU16(kMaxUdpPayloadSize);     // class
    // ttl (next 3 fields)
    writer.WriteU8(0);  // rcode does not apply to requests
    writer.WriteU8(0);  // version
    // TODO(robpercival): Set "DNSSEC OK" flag if/when DNSSEC is supported:
    // https://tools.ietf.org/html/rfc3225#section-3
    writer.WriteU16(0);  // flags

    // rdata
    writer.WriteU16(merged_opt_rdata.value().buf().size());  // rdata length
    writer.WriteBytes(merged_opt_rdata.value().buf().data(),
                      merged_opt_rdata.value().buf().size());
  }
  */
}

bool DnsQuery::is_compressed() const{	
  return compressed;
}

DnsQuery::DnsQuery(scoped_refptr<IOBufferWithSize> buffer)
    : io_buffer_(std::move(buffer)) {}

DnsQuery::DnsQuery(const DnsQuery& query) {
  CopyFrom(query);
}

DnsQuery& DnsQuery::operator=(const DnsQuery& query) {
  CopyFrom(query);
  return *this;
}

DnsQuery::~DnsQuery() = default;

std::unique_ptr<DnsQuery> DnsQuery::CloneWithNewId(uint16_t id) const {
  VLOG(1) << "[breakerspace] DnsQuery::CloneWithNewId";
  return base::WrapUnique(new DnsQuery(*this, id));
}

bool DnsQuery::Parse(size_t valid_bytes) {
  VLOG(1) << "[breakerspace] DnsQuery::Parse()";
  if (io_buffer_ == nullptr || io_buffer_->data() == nullptr) {
    return false;
  }
  CHECK(valid_bytes <= base::checked_cast<size_t>(io_buffer_->size()));
  // We should only parse the query once if the query is constructed from a raw
  // buffer. If we have constructed the query from data or the query is already
  // parsed after constructed from a raw buffer, |header_| is not null.
  DCHECK(header_ == nullptr);
  base::BigEndianReader reader(
      reinterpret_cast<const uint8_t*>(io_buffer_->data()), valid_bytes);
  dns_protocol::Header header;
  if (!ReadHeader(&reader, &header)) {
    return false;
  }
  if (header.flags & dns_protocol::kFlagResponse) {
    return false;
  }

  /*
   * [breakerspace] commenting this if statement out
   * seems unnecessary (it didn't make a difference when I
   * uncommented it) but I'll leave it uncommented to be 
   * safe
  if (header.qdcount != 1) {
    VLOG(1) << "Not supporting parsing a DNS query with multiple (or zero) "
               "questions.";
    return false;
  }
  */
  std::string qname;
  if (!ReadName(&reader, &qname)) {
    return false;
  }
  uint16_t qtype;
  uint16_t qclass;
  if (!reader.ReadU16(&qtype) || !reader.ReadU16(&qclass) ||
      qclass != dns_protocol::kClassIN) {
    return false;
  }
  // |io_buffer_| now contains the raw packet of a valid DNS query, we just
  // need to properly initialize |qname_size_| and |header_|.
  qname_size_ = qname.size();
  header_ = reinterpret_cast<dns_protocol::Header*>(io_buffer_->data());
  return true;
}

uint16_t DnsQuery::id() const {
  return base::NetToHost16(header_->id);
}

base::StringPiece DnsQuery::qname() const {
  if (!compressed) {
    return base::StringPiece(io_buffer_->data() + kHeaderSize, qname_size_);
  } else {
    return base::StringPiece(io_buffer_uncompressed->data() + kHeaderSize, qname_size_);
  }
}

uint16_t DnsQuery::qtype() const {
  uint16_t type;
  if(!compressed) {

  	base::ReadBigEndian(reinterpret_cast<const uint8_t*>(
                          io_buffer_->data() + kHeaderSize + qname_size_),
                     &type);
  } else {
	base::ReadBigEndian(reinterpret_cast<const uint8_t*>(
			  io_buffer_uncompressed->data() + kHeaderSize + qname_size_), 
		       &type);
  }
  return type;
}

base::StringPiece DnsQuery::question() const {
  if (!compressed) {
  	return base::StringPiece(io_buffer_->data() + kHeaderSize,
                           QuestionSize(qname_size_));
  } else {
	VLOG(1) << "[breakerspace] Uncompressed being returned";
	return base::StringPiece(io_buffer_uncompressed->data() + kHeaderSize, 
				QuestionSize(qname_size_));
  }
}

size_t DnsQuery::question_size() const {
  return QuestionSize(qname_size_);
}

void DnsQuery::set_flags(uint16_t flags) {
  VLOG(1) << "[breakerspace] DnsQuery::set_flags( " << flags << " )";
  header_->flags = flags;
}

DnsQuery::DnsQuery(const DnsQuery& orig, uint16_t id) {
  VLOG(1) << "[breakerspace] DNSQuery::CopyFrom(2 params)";
  CopyFrom(orig);
  header_->id = base::HostToNet16(id);
}

void DnsQuery::CopyFrom(const DnsQuery& orig) {
  VLOG(1) << "[breakerspace] DNSQuery::CopyFrom(1 param)";
  qname_size_ = orig.qname_size_;
  io_buffer_ = base::MakeRefCounted<IOBufferWithSize>(orig.io_buffer()->size());
  memcpy(io_buffer_.get()->data(), orig.io_buffer()->data(),
         io_buffer_.get()->size());
  header_ = reinterpret_cast<dns_protocol::Header*>(io_buffer_->data());

  compressed = orig.compressed;
  
  if (compressed) {
    io_buffer_uncompressed = base::MakeRefCounted<IOBufferWithSize>(orig.io_buffer_uncompressed.get()->size());
    memcpy(io_buffer_uncompressed.get()->data(), orig.io_buffer_uncompressed.get()->data(), io_buffer_uncompressed.get()->size());
  }

  strategy = orig.strategy;
}

bool DnsQuery::ReadHeader(base::BigEndianReader* reader,
                          dns_protocol::Header* header) {
  VLOG(1) << "[breakerspace] DNSQuery::ReadHeader()";
  return (
      reader->ReadU16(&header->id) && reader->ReadU16(&header->flags) &&
      reader->ReadU16(&header->qdcount) && reader->ReadU16(&header->ancount) &&
      reader->ReadU16(&header->nscount) && reader->ReadU16(&header->arcount));
}

bool DnsQuery::ReadName(base::BigEndianReader* reader, std::string* out) {
  DCHECK(out != nullptr);
  VLOG(1) << "[breakerspace] DNSQuery::ReadName()";
  out->clear();
  out->reserve(dns_protocol::kMaxNameLength + 1);
  uint8_t label_length;
  if (!reader->ReadU8(&label_length)) {
    return false;
  }
  while (label_length) {
    if (out->size() + 1 + label_length > dns_protocol::kMaxNameLength) {
      return false;
    }

    out->append(reinterpret_cast<char*>(&label_length), 1);

    base::StringPiece label;
    if (!reader->ReadPiece(&label, label_length)) {
      return false;
    }
    out->append(label.data(), label.size());
    if (!reader->ReadU8(&label_length)) {
      return false;
    }
  }
  DCHECK_LE(out->size(), static_cast<size_t>(dns_protocol::kMaxNameLength));
  out->append(1, '\0');
  return true;
}

} // namespace net
