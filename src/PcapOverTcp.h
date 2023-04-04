// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_PCAP_OVER_TCP_SOURCE_H
#define IOSOURCE_PKTSRC_PCAP_OVER_TCP_SOURCE_H

extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <errno.h>          // errorno
#include <unistd.h>         // close()

#include <net/ethernet.h>      // ETH_P_ALL
#include <linux/if.h>          // ifreq
#include <linux/if_packet.h>   // AF_PACKET, etc.
#include <linux/sockios.h>     // SIOCSHWTSTAMP
#include <linux/net_tstamp.h>  // hwtstamp_config
#include <pcap.h>
}

#include "zeek/iosource/PktSrc.h"

namespace zeek::iosource::pktsrc {

class PcapOverTcpSource : public zeek::iosource::PktSrc {
public:
	/**
	 * Constructor.
	 *
	 * path: Name of the interface to open (the PcapOverTcp source doesn't
	 * support reading from files).
	 *
	 * is_live: Must be true (the AF_Packet source doesn't support offline
	 * operation).
	 */
	PcapOverTcpSource(const std::string& path, bool is_live);

	/**
	 * Destructor.
	 */
	virtual ~PcapOverTcpSource();

	static PktSrc* InstantiatePcapOverTcp(const std::string& path, bool is_live);

protected:
	// PktSrc interface.
	virtual void Open();
	virtual void Close();
	virtual bool ExtractNextPacket(zeek::Packet* pkt);
	virtual void DoneWithPacket();
	virtual bool PrecompileFilter(int index, const std::string& filter);
	virtual bool SetFilter(int index);
	virtual void Statistics(Stats* stats);

private:
	Properties props;
	Stats stats;

	int current_filter;
	pcap_t * pcap;

	unsigned int num_discarded;

	int socket_fd;
	struct pcap_pkthdr current_hdr;

};

}

#endif
