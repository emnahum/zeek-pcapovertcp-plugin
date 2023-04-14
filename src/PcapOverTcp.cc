
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

static int zpot_set_socket_buffer_size(int socket_fd);
static int zpot_connect_to_server(int socket_fd, std::string server_ip, int port_number);
static int zpot_get_serverip_and_port(const std::string& path, std::string &server_ip, int * port);
static int zpot_get_global_header(int socket_fd, pcap_file_header & global_hdr);
static int zpot_get_packet_header(int socket_fd, pcap_pkthdr & current_hdr);
static int zpot_get_packet_body(int socket_fd, char * buffer, int bufsize, int bytes_expected);

using namespace zeek::iosource::pktsrc;

plugin::Zeek_PcapOverTcp::Plugin PcapOverTcpFoo;

PcapOverTcpSource::~PcapOverTcpSource()
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Destructor: Entry");
	Close();
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Destructor: Exit");
}

//
//	Constructor -- just sets up and instantiates the object.
//
//	We don't actually open the socket until Open() is called.
//
PcapOverTcpSource::PcapOverTcpSource(const std::string& path, bool is_live)
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Constructor: Entry");
	// does PCAP over TCP support live or non-live traffic?j
	if ( ! is_live )
		Error("PcapOverTcp source does not support offline input");

	current_filter = -1;
	props.path = path;
	props.is_live = is_live;

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Constructor: Exit");
}

// 	open the socket as a packet source
void PcapOverTcpSource::Open()
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Open: Entry");

	// create socket
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Open: creating socket");
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if ( socket_fd < 0 )
	{
		Error(errno ? strerror(errno) : "unable to create socket");
		return;
	}


	// set the socket params
	int rv = zpot_set_socket_buffer_size(socket_fd);
	if (rv < 0)
	{
		Error(errno ? strerror(errno) : "warning: unable to set socket opts");
	}

	// are we a client or a server?  Just a client for now.
	std::string server_ip;
	int port;

	// get IP address and port to connect to
	if (zpot_get_serverip_and_port(props.path, server_ip, &port) < 0)
	{
		Error(errno ? strerror(errno) : "Invalid IP:PORT address format");
		return;
	}

	// now try to connect to server
	if (zpot_connect_to_server(socket_fd, server_ip, port) < 0)
	{
		Error(errno ? strerror(errno) : "unable to connect");
		close(socket_fd);
		return;
	}

	// get the initial global header
	pcap_file_header global_hdr;
	
	ssize_t bytes_received = zpot_get_global_header(socket_fd, global_hdr);
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
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Open: Exit");
}

void PcapOverTcpSource::Close()
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Close: Entry");
	if ( ! socket_fd )
		return;

	close(socket_fd);
	socket_fd = 0;

	Closed();
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Close: Exit");
}

bool PcapOverTcpSource::ExtractNextPacket(zeek::Packet* pkt)
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "ExtractNext: Entry");
	if ( ! socket_fd ) 
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "ExtractNext: socket is closed");
		return false;
	}

	while ( true )
	{
		// read the next packet off the socket
		char   buffer[64*1024];
		const u_char *data = (u_char *) buffer;
		int bytes_received;
	
		// get the packet header first
		bytes_received = zpot_get_packet_header(socket_fd, current_hdr); 
				
		// less than zero means error
		if (bytes_received < 0) 
		{
			Error(errno ? strerror(errno) : "error reading socket");
			return false;
		}

		// check for EOF (bytes=0)
		if (bytes_received == 0) 
		{
			// socket is out of data
			PLUGIN_DBG_LOG(PcapOverTcpFoo, "ExtractNext: OOD");
			close(socket_fd);
			return false;
		}

		// check the header length isn't crazy
		if (current_hdr.caplen > sizeof(buffer))
		{
			PLUGIN_DBG_LOG(PcapOverTcpFoo, "ExtractNext: Crazy");
			close(socket_fd);
			return false;
		}

		// now read the full packet
		bytes_received = zpot_get_packet_body(socket_fd, buffer, sizeof(buffer), 
				current_hdr.caplen);
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
			PLUGIN_DBG_LOG(PcapOverTcpFoo, "ExtractNext: OOD2");
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
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "ExtractNext: Exit");
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
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "SetFilter: Open");
	current_filter = index;
	return true;
}

bool PcapOverTcpSource::PrecompileFilter(int index, const std::string& filter)
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Precompile: Open");
	return PktSrc::PrecompileBPFFilter(index, filter);
}

// get the statistics for the packet source
void PcapOverTcpSource::Statistics(Stats* s)
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Stats: Open");
	if ( ! socket_fd )
	{
		s->received = s->bytes_received = s->link = s->dropped = 0;
		return;
	}

	memcpy(s, &stats, sizeof(Stats));
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Stats: Exit");
}

zeek::iosource::PktSrc* PcapOverTcpSource::InstantiatePcapOverTcp(const std::string& path, bool is_live)
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "Instantiate: Entry");
	return new PcapOverTcpSource(path, is_live);
}

// set the socket buffer size
static int zpot_set_socket_buffer_size(int socket_fd)
{
        // get options
        int request_buffer_size = zeek::BifConst::PcapOverTcp::buffer_size;
        int current_buffer_size;
	unsigned int option_len = sizeof(current_buffer_size);
        int rv;

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_set_socket_buffer_size: entry");
        // get the current socket params
        rv = getsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &current_buffer_size, &option_len);
                        //static_cast<socklen_t>(sizeof(current_buffer_size)));
        if (rv < 0)
        {
                PLUGIN_DBG_LOG(PcapOverTcpFoo,
                        "zpot_set_socket_buffer_size: error retrieving buffer");
                return -1;
        }

        // is request more than current?
        if (request_buffer_size < current_buffer_size)
        {
                PLUGIN_DBG_LOG(PcapOverTcpFoo,
                        "zpot_set_socket_buffer_size: request %d is smaller than current %d",
                        request_buffer_size, current_buffer_size);
                return -1;
        }

        // set the current socket params
        rv = setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &request_buffer_size,
                        sizeof(request_buffer_size));
        if (rv < 0)
        {
                PLUGIN_DBG_LOG(PcapOverTcpFoo,
                        "zpot_set_socket_buffer_size: error setting buffer size");
                return -1;
        }
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_set_socket_buffer_size: set to %d",
			request_buffer_size);
        return 0;
}

// 	get the global header.  Return bytes_received:
// 	< 0 : error
// 	= 0 : socket is closed, EOF
// 	< sizeof(sf_pkthdr) : error
// 	= sizeof(sf_pkthdr) : OK
static int  zpot_get_global_header(int socket_fd, pcap_file_header & global_hdr)
{	
	int bytes_received;

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: entry"); 
	do {
		bytes_received = recv(socket_fd, &global_hdr, sizeof(global_hdr), 
				MSG_WAITALL);
	} while ((bytes_received == -1) && (errno == EINTR));

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: bytes_received is %d", 
			bytes_received);
	if (bytes_received < -1)
	{
		return -1;
	}
	
	if (bytes_received < (int) sizeof(global_hdr)) 
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: ONLY got %x bytes",
				bytes_received);
		return -1;
	}

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: magic is %x",         
			global_hdr.magic);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: version_major is %d", 
			global_hdr.version_major);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: version_minor is %d", 
			global_hdr.version_minor);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: thiszone is %d",      
			global_hdr.thiszone);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: sigfigs is %d",       
			global_hdr.sigfigs);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: snaplen is %d",       
			global_hdr.snaplen);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: linktype is %d",      
			global_hdr.linktype);
	return bytes_received;
}

//	get the server IP address and port number.  -1 means error, 0 OK
static int zpot_get_serverip_and_port(const std::string& path, std::string &server_ip, int * port)
{
	// find the IP addr and port of server
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_serverip_and_port: path is %s", 
			path.c_str());
	size_t colon_pos = path.find(':');
	if (colon_pos == std::string::npos) 
	{
		return -1;
	}

	// Extract the IP address and port number as separate strings
	server_ip = path.substr(0, colon_pos);
	std::string port_str = path.substr(colon_pos + 1);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_serverip_and_port: server_ip is %s", 
			server_ip.c_str());
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_serverip_and_port: port_str is %s",  
			port_str.c_str());

	// Convert the port number string to an integer
	int port_number = std::stoi(port_str);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_serverip_and_port: port_number is %d", 
			port_number );
	*port = port_number;
	return 0;
}

//	connect to the server.  -1 is an error, 0 is OK
static int zpot_connect_to_server(int socket_fd, std::string server_ip, int port_number)
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_connect_to_server: Connecting... ");
	// setup server_addr for connect
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
	server_addr.sin_port = htons(port_number);

	int delay = 1;
	int rv;
	// Connect to the server
	do 
	{
		// attempt to connect
		rv = connect(socket_fd, reinterpret_cast<sockaddr*>(&server_addr), 
			sizeof(server_addr));
		// if failure is ECONNREFUSED...
		if ((rv == -1) && (errno == ECONNREFUSED))
		{
			// sleep, then try again
			PLUGIN_DBG_LOG(PcapOverTcpFoo, 
					"zpot_connect_to_server: ECONNREFUSED %d",
					delay);
			sleep(delay);
			delay += delay;
		}
	} while ((delay < 16) && (rv == -1));

	if ( rv < 0 ) 
	{
		// didn't make it
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_connect_to_server: failed ");
		return -1;
	}
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_connect_to_server: Connected ");

	return 0;
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

// 	get the pcap_pkthdr for the packet.  Return bytes_received:
// 	< 0 : error
// 	= 0 : socket is closed, EOF
// 	!= sizeof(sf_packethdr) : error
// 	= sizeof(sf_packethdr) : OK
static int zpot_get_packet_header(int socket_fd, pcap_pkthdr & current_hdr)
{
	int bytes_received;
	struct pcap_sf_pkthdr sf_pkthdr;

	do {
		bytes_received = recv(socket_fd, &sf_pkthdr, sizeof(sf_pkthdr), MSG_WAITALL);
	} while ((bytes_received == -1) && (errno == EINTR));

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: bytes_received is %d",
			bytes_received);
	if (bytes_received < 0)
	{
		return -1;
	}

	// check for EOF
	if (bytes_received == 0)
	{
		return 0;
	}

	if (bytes_received != sizeof(sf_pkthdr))
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: ONLY got %x bytes",
				bytes_received);
		return -1;
	}

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: time is   %d",
			sf_pkthdr.ts.tv_sec);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: utime is  %d",
			sf_pkthdr.ts.tv_usec);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: len is    %d",
			sf_pkthdr.len);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: caplen is %d",
			sf_pkthdr.caplen);

	// copy over from sf header to packet header, which Zeek expects
	current_hdr.ts.tv_sec = sf_pkthdr.ts.tv_sec;
	current_hdr.ts.tv_usec = sf_pkthdr.ts.tv_usec;
	current_hdr.len = sf_pkthdr.len;
	current_hdr.caplen = sf_pkthdr.caplen;

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: checked hdr len");
	return bytes_received;
}

// 	get the full packet from the socket. Return bytes_received:
// 	< 0 : error
// 	  0 : socket is closed, EOF
// 	< bytes_expected : issue warning (not fatal, should it be?)
// 	= bytes_expected : OK
static int zpot_get_packet_body(int socket_fd, char * buffer, int bufsize, int bytes_expected)
{
	int bytes_received;

	// check for overrun of buffer
	if (bufsize < bytes_expected)
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, 
		"zpot_get_packet_body: bufsize %d is smaller than bytes_expected is %d",
				bufsize, bytes_expected);
		return -1;
	}

	do {
		bytes_received = recv(socket_fd, buffer, bytes_expected, MSG_WAITALL);
	} while ((bytes_received == -1) && (errno == EINTR));

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_body: bytes_received is %d",
			bytes_received);
	if (bytes_received < 0)
	{
		return -1;
	}

	// EOF will probably be caught above, so probably don't need this,
	// but just in case...
	if (bytes_received == 0)
	{
		// socket is out of data
		return 0;
	}
	if (bytes_received != bytes_expected)
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_body: ONLY %d bytes_received",
				bytes_received);
	}
	return bytes_received;
}
