
#include "zeek/zeek-config.h"

// Starting with Zeek 6.0, zeek-config.h does not provide the
// ZEEK_VERSION_NUMBER macro anymore when compiling a included
// plugin. Use the new zeek/zeek-version.h header if it exists.
#if __has_include("zeek/zeek-version.h")
#include "zeek/zeek-version.h"
#endif

#include "PcapOverTcp.h"

#include "pcapovertcp.bif.h"

// CentOS 7 if_packet.h does not yet have this define, provide it
// explicitly if missing.
#ifndef TP_STATUS_CSUM_VALID
#define TP_STATUS_CSUM_VALID (1 << 7)
#endif

using namespace zeek::iosource::pktsrc;

PcapOverTcpSource::~PcapOverTcpSource()
{
	Close();
}

//
//	Contstructor -- just sets up and instantiates the object.
//
//	We don't actually open the socket until Open() is called.
//
PcapOverTcpSource::PcapOverTcpSource(const std::string& path, bool is_live)
{
	Info("PcapOverTcpSource: Entry");
	// does PCAP over TCP support live or non-live traffic?j
	if ( ! is_live )
		Error("PcapOverTcp source does not support offline input");

	current_filter = -1;
	props.path = path;
	props.is_live = is_live;

	// does PCAP over TCP support checksum offloads?
	checksum_mode = zeek::BifConst::PcapOverTcp::checksum_validation_mode->AsEnum();
	Info("PcapOverTcpSource: Exit");
}

void PcapOverTcpSource::Open()
{
	Info("PcapOverTcpSource::Open Entry");
	// grab various constants defined in .bif file.
	uint64_t buffer_size = zeek::BifConst::PcapOverTcp::buffer_size;
	uint64_t block_size = zeek::BifConst::PcapOverTcp::block_size;
	int block_timeout_msec = static_cast<int>(zeek::BifConst::PcapOverTcp::block_timeout * 1000.0);
	// create socket
	Info("PcapOverTcpSource::Open creating socket");
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if ( socket_fd < 0 )
	{
		Error(errno ? strerror(errno) : "unable to create socket");
		return;
	}

	// set the socket params?
	// are we a client or a server?  Just a client for now.

	// find the IP addr and port of server
	Info(util::fmt("PcapOverTcpSource::Open path is %s", props.path.c_str()));
	size_t colon_pos = props.path.find(':');
	if (colon_pos == std::string::npos) 
	{
		Error(errno ? strerror(errno) : "Invalid IP:PORT address format");
		return;
	}

	// Extract the IP address and port number as separate strings
	std::string server_ip = props.path.substr(0, colon_pos);
	std::string port_str = props.path.substr(colon_pos + 1);

	Info(util::fmt("PcapOverTcpSource::Open server_ip is %s", server_ip.c_str()));
	Info(util::fmt("PcapOverTcpSource::Open port_str is %s",  port_str.c_str()));
	// Convert the port number string to an integer
	int port_number = std::stoi(port_str);
	Info(util::fmt("PcapOverTcpSource::Open port_number is %d", port_number ));
	
	// setup server_addr for connect
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
	server_addr.sin_port = htons(port_number);

	// Connect to the server
	int rv = connect(socket_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));
	if ( rv < 0 ) 
	{
		Error(errno ? strerror(errno) : "unable to connect");
		close(socket_fd);
		return;
	}
	Info("PcapOverTcpSource::Open Connected ");

	// get the initial global header
	pcap_file_header global_hdr;
	ssize_t bytes_received = recv(socket_fd, &global_hdr, sizeof(global_hdr), 0);
	Info(util::fmt("PcapOverTcpSource::Open bytes_received is %d", 
				static_cast<int>(bytes_received)));
	if (bytes_received < 0) 
	{
		Error(errno ? strerror(errno) : "error reading socket");
		close(socket_fd);
		return;
	}

	Info(util::fmt("PcapOverTcpSource::Open magic is %ud",        global_hdr.magic));
	Info(util::fmt("PcapOverTcpSource::Open version_major is %d", global_hdr.version_major));
	Info(util::fmt("PcapOverTcpSource::Open version_major is %d", global_hdr.version_minor));
	Info(util::fmt("PcapOverTcpSource::Open sigfigs is %d",       global_hdr.sigfigs));
	Info(util::fmt("PcapOverTcpSource::Open linktype is %d",      global_hdr.linktype));

	props.netmask = NETMASK_UNKNOWN;
	props.selectable_fd = socket_fd;
	props.is_live = true;
	props.link_type = global_hdr.linktype;

	stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
	num_discarded = 0;

	Opened(props);
	Info("PcapOverTcpSource::Open Exit");
}

void PcapOverTcpSource::Close()
{
	Info("PcapOverTcpSource::Close Entry");
	if ( ! socket_fd )
		return;

	close(socket_fd);
	socket_fd = 0;

	Closed();
	Info("PcapOverTcpSource::Close Exit");
}

bool PcapOverTcpSource::ExtractNextPacket(zeek::Packet* pkt)
{
	Info("PcapOverTcpSource::Extract Entry");
	if ( ! socket_fd )
		return false;

	while ( true )
	{
		// read the next packet off the socket
		char   buffer[PCAP_ERRBUF_SIZE];
		const u_char *data = (u_char *) buffer;
	
		// get the header first	
		ssize_t bytes_received = recv(socket_fd, &current_hdr, sizeof(current_hdr), 0);
		Info(util::fmt("PcapOverTcpSource::Extract bytes_received 1 is %d", 
					static_cast<int>(bytes_received)));
		if (bytes_received < 0) 
		{
			Error(errno ? strerror(errno) : "error reading socket");
			close(socket_fd);
			return false;
		}

		Info(util::fmt("PcapOverTcpSource::Extract len is %d", current_hdr.len));
		Info(util::fmt("PcapOverTcpSource::Extract caplen is %d", current_hdr.caplen));
		Info(util::fmt("PcapOverTcpSource::Extract time is %ld", current_hdr.ts.tv_sec));
		Info(util::fmt("PcapOverTcpSource::Extract utime is %ld", current_hdr.ts.tv_usec));

		// check the header length isn't crazy
		if (current_hdr.len > sizeof(buffer))
		{
			Error(errno ? strerror(errno) : "header length problem");
			close(socket_fd);
			return false;
		}
		Info("PcapOverTcpSource::Extract checked hdr len");

		// now read the packet
		bytes_received = recv(socket_fd, buffer, current_hdr.len, 0);
		Info(util::fmt("PcapOverTcpSource::Extract bytes_received 2 is %d", 
					static_cast<int>(bytes_received)));
		if (bytes_received < 0) 
		{
			Error(errno ? strerror(errno) : "error reading socket");
			close(socket_fd);
			return false;
		}

		// apply the BFF Filter
		if ( !ApplyBPFFilter(current_filter, &current_hdr, data) )
		{
			++num_discarded;
			DoneWithPacket();
			continue;
		}

		// call pkt-Init()
		pkt->Init(props.link_type, &current_hdr.ts, current_hdr.caplen, current_hdr.len, data);

		if ( current_hdr.len == 0 || current_hdr.caplen == 0 )
		{
			Weird("empty current header", pkt);
			return false;
		}

		// update stats
		stats.received++;
		stats.bytes_received += current_hdr.len;
		Info("PcapOverTcpSource::Extract Exit");
		return true;
	}

	// NOTREACHED
	return false;
}

void PcapOverTcpSource::DoneWithPacket()
{
		// Nothing to do.
}

bool PcapOverTcpSource::SetFilter(int index)
{
	current_filter = index;
	return true;
}

bool PcapOverTcpSource::PrecompileFilter(int index, const std::string& filter)
{
	return PktSrc::PrecompileBPFFilter(index, filter);
}

// get the statistics for the packet source
void PcapOverTcpSource::Statistics(Stats* s)
{
	if ( ! socket_fd )
	{
		s->received = s->bytes_received = s->link = s->dropped = 0;
		return;
	}

	struct tpacket_stats_v3 tp_stats;
	socklen_t tp_stats_len = sizeof (struct tpacket_stats_v3);
	int ret;

	ret = getsockopt(socket_fd, SOL_PACKET, PACKET_STATISTICS, &tp_stats, &tp_stats_len);
	if ( ret < 0 )
	{
		Error(errno ? strerror(errno) : "unable to retrieve statistics");
		s->received = s->bytes_received = s->link = s->dropped = 0;
		return;
	}

	stats.link += tp_stats.tp_packets;
	stats.dropped += tp_stats.tp_drops;

	memcpy(s, &stats, sizeof(Stats));
}

zeek::iosource::PktSrc* PcapOverTcpSource::InstantiatePcapOverTcp(const std::string& path, bool is_live)
{
	return new PcapOverTcpSource(path, is_live);
}
