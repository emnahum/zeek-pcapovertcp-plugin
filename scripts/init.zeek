##! Packet source using PCAP over TCP.
##!
##! Note: This module is in testing and is not yet considered stable!

module PcapOverTcp;

export {
	## Size of the socket-buffer.
	const buffer_size = 32 * 1024 * 1024 &redef;
}
