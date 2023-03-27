##! Packet source using PCAP over TCP.
##!
##! Note: This module is in testing and is not yet considered stable!

module PcapOverTcp;

export {
	## Size of the ring-buffer.
	const buffer_size = 128 * 1024 * 1024 &redef;
	## Size of an individual block. Needs to be a multiple of page size.
	const block_size = 4096 * 8 &redef;
	## Retire timeout for a single block.
	const block_timeout = 10msec &redef;
	## Link type (default Ethernet).
	const link_type = 1 &redef;
	## Checksum validation mode.
	const checksum_validation_mode: ChecksumMode = CHECKSUM_ON &redef;
}
