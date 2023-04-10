
#include "zeek/zeek-config.h"
#include "zeek/DebugLogger.h"
#include "Plugin.h"


// Starting with Zeek 6.0, zeek-config.h does not provide the
// ZEEK_VERSION_NUMBER macro anymore when compiling a included
// plugin. Use the new zeek/zeek-version.h header if it exists.
#if __has_include("zeek/zeek-version.h")
#include "zeek/zeek-version.h"
#endif

#include "PcapOverTcp.h"

#include "pcapovertcp.bif.h"

using namespace zeek::iosource::pktsrc;

plugin::Zeek_PcapOverTcp::Plugin PcapOverTcpFoo;

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
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource: Constructor Entry");
	// does PCAP over TCP support live or non-live traffic?j
	if ( ! is_live )
		Error("PcapOverTcp source does not support offline input");

	current_filter = -1;
	props.path = path;
	props.is_live = is_live;

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource: Constructor Exit");
}

void PcapOverTcpSource::Open()
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open Entry");
	
	// create socket
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open creating socket");
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if ( socket_fd < 0 )
	{
		Error(errno ? strerror(errno) : "unable to create socket");
		return;
	}

	// set the socket params?
	// are we a client or a server?  Just a client for now.

	std::string server_ip;
	int port;

	// get IP address and port to connect to
	if (zpot_get_addr_and_port(props.path, server_ip, &port) < 1)
	{
		Error(errno ? strerror(errno) : "Invalid IP:PORT address format");
		return;
	}

	// now try to connect to server
	if (zpot_connect_to_server(socket_fd, server_ip, port) < 1)
	{
		Error(errno ? strerror(errno) : "unable to connect");
		close(socket_fd);
		return;
	}

	// get the initial global header
	pcap_file_header global_hdr;
	
	ssize_t bytes_received = zpot_get_global_hdr(socket_fd, global_hdr);
	if (bytes_received != sizeof(global_hdr))
	{
		Error(errno ? strerror(errno) : "error reading socket");
		close(socket_fd);
		return;
	}

	// fill in props
	props.netmask = NETMASK_UNKNOWN;
	props.selectable_fd = socket_fd;
	props.is_live = true;
	props.link_type = global_hdr.linktype;

	stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
	num_discarded = 0;

	Opened(props);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open Exit");
}

void PcapOverTcpSource::Close()
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Close Entry");
	if ( ! socket_fd )
		return;

	close(socket_fd);
	socket_fd = 0;

	Closed();
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Close Exit");
}

// stolen from libpcap/pcap-int.h.  Not exported by libpcap
struct pcap_timeval {
     bpf_int32 tv_sec;           /* seconds */
     bpf_int32 tv_usec;          /* microseconds */
};

struct pcap_sf_pkthdr {
     struct pcap_timeval ts;     /* time stamp */
     bpf_u_int32 caplen;         /* length of portion present */
     bpf_u_int32 len;            /* length of this packet (off wire) */
};

bool PcapOverTcpSource::ExtractNextPacket(zeek::Packet* pkt)
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract Entry");
	if ( ! socket_fd ) 
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract socket is closed");
		return false;
	}

	while ( true )
	{
		// read the next packet off the socket
		char   buffer[64*1024];
		const u_char *data = (u_char *) buffer;
		struct pcap_sf_pkthdr sf_pkthdr;
		int bytes_received;
	
		// get the sf header first
		do {
                	bytes_received = recv(socket_fd, &sf_pkthdr, sizeof(sf_pkthdr), 
				   MSG_WAITALL);
                } while ((bytes_received == -1) && (errno == EINTR));
  
		PLUGIN_DBG_LOG(PcapOverTcpFoo, 
				"PcapOverTcpSource::Extract header bytes_received is %d", 
		 		static_cast<int>(bytes_received));
		if (bytes_received < 0) 
		{
			Error(errno ? strerror(errno) : "error reading socket");
			return false;
		}

		// check for EOF
		if (bytes_received == 0) 
		{
			// socket is out of data
			PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract OOD");
			close(socket_fd);
			return false;
		}

		PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract time is   %d", 
				sf_pkthdr.ts.tv_sec);
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract utime is  %d", 
				sf_pkthdr.ts.tv_usec);
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract len is    %d", 
				sf_pkthdr.len);
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract caplen is %d", 
				sf_pkthdr.caplen);

		// copy over from sf header to packet header, which Zeek expects	
		current_hdr.ts.tv_sec = sf_pkthdr.ts.tv_sec;
		current_hdr.ts.tv_usec = sf_pkthdr.ts.tv_usec;
		current_hdr.len = sf_pkthdr.len;
		current_hdr.caplen = sf_pkthdr.caplen;

		// check the header length isn't crazy
		if (current_hdr.caplen > sizeof(buffer))
		{
			Error(errno ? strerror(errno) : "header length problem");
			return false;
		}
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract checked hdr len");

		// now read the packet
		bytes_received = recv(socket_fd, buffer, current_hdr.caplen, MSG_WAITALL);
		PLUGIN_DBG_LOG(PcapOverTcpFoo, 
				"PcapOverTcpSource::Extract buffer bytes_received is %d", 
				static_cast<int>(bytes_received));
		if (bytes_received < 0) 
		{
			Error(errno ? strerror(errno) : "error reading socket");
			return false;
		}
	
		// EOF will probably be caught above, so probably don't need this, 
		// but just in case...	
		if (bytes_received == 0) 
		{
			// socket is out of data
			PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract OOD2");
			close(socket_fd);
			return false;
		}

		PLUGIN_DBG_LOG(PcapOverTcpFoo, 
				"PcapOverTcpSource::Extract caplen is same as recv len (%d)", 
				current_hdr.caplen);
		
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
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Extract Exit");
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
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Stats Open");
	if ( ! socket_fd )
	{
		s->received = s->bytes_received = s->link = s->dropped = 0;
		return;
	}

	memcpy(s, &stats, sizeof(Stats));
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Stats Exit");
}

zeek::iosource::PktSrc* PcapOverTcpSource::InstantiatePcapOverTcp(const std::string& path, bool is_live)
{
	return new PcapOverTcpSource(path, is_live);
}


int zpot_get_global_hdr(int socket_fd, pcap_file_header & global_hdr)
{	
	int bytes_received = recv(socket_fd, &global_hdr, sizeof(global_hdr), MSG_WAITALL);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open bytes_received is %d", 
			bytes_received);
	if (bytes_received < (int) sizeof(global_hdr)) 
	{
		return -1;
	}

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open magic is %x",         
			global_hdr.magic);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open version_major is %d", 
			global_hdr.version_major);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open version_minor is %d", 
			global_hdr.version_minor);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open thiszone is %d",      
			global_hdr.thiszone);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open sigfigs is %d",       
			global_hdr.sigfigs);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open snaplen is %d",       
			global_hdr.snaplen);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open linktype is %d",      
			global_hdr.linktype);
	return bytes_received;
};

int zpot_get_addr_and_port(const std::string& path, std::string &server_ip, int * port)
{
	// find the IP addr and port of server
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open path is %s", 
			path.c_str());
	size_t colon_pos = path.find(':');
	if (colon_pos == std::string::npos) 
	{
		return -1;
	}

	// Extract the IP address and port number as separate strings
	server_ip = path.substr(0, colon_pos);
	std::string port_str = path.substr(colon_pos + 1);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open server_ip is %s", 
			server_ip.c_str());
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open port_str is %s",  
			port_str.c_str());

	// Convert the port number string to an integer
	int port_number = std::stoi(port_str);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open port_number is %d", 
			port_number );
	*port = port_number;
	return 0;
}

int zpot_connect_to_server(int socket_fd, std::string server_ip, int port_number)
{
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
		return -1;
	}
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "PcapOverTcpSource::Open Connected ");

	return 0;
}

