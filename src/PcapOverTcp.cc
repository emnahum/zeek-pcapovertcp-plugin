
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
static int zpot_get_server_name_and_port(const std::string & path, std::string &server_name, int * port);
static int zpot_resolve_server_name(std::string server_name, std::string &server_ip);
static int zpot_connect_to_server_ip(int socket_fd, std::string server_ip, int port_number);
static int zpot_get_global_header(int socket_fd, pcap_file_header & global_hdr, bool & swapped);
static int zpot_get_packet_header(int socket_fd, pcap_pkthdr & current_hdr, bool swapped);
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
	std::string server_name;
	int port;

	// get IP address and port to connect to
	if (zpot_get_server_name_and_port(props.path, server_name, &port) < 0)
	{
		Error(errno ? strerror(errno) : "Invalid DNSNAME:PORT address format");
		return;
	}

	/* server IP address */
	std::string server_ip;

	// resolve the server name to IP
	if (zpot_resolve_server_name(server_name, server_ip) < 0)
	{
		Error(errno ? strerror(errno) : "unable to resolve");
		close(socket_fd);
		return;
	}

	// now try to connect to server
	if (zpot_connect_to_server_ip(socket_fd, server_ip, port) < 0)
	{
		Error(errno ? strerror(errno) : "unable to connect");
		close(socket_fd);
		return;
	}

	// get the initial global header
	pcap_file_header global_hdr;
	
	ssize_t bytes_received = zpot_get_global_header(socket_fd, global_hdr, swapped);
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
		bytes_received = zpot_get_packet_header(socket_fd, current_hdr, swapped); 
				
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
			// close(socket_fd);
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
			// close(socket_fd);
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

// stolen from libpcap/pcap-util.h.  Not exported by libpcap

#define SWAPLONG(y) \
      (((((u_int)(y))&0xff)<<24) | \
       ((((u_int)(y))&0xff00)<<8) | \
       ((((u_int)(y))&0xff0000)>>8) | \
       ((((u_int)(y))>>24)&0xff))
#define SWAPSHORT(y) \
       ((u_short)(((((u_int)(y))&0xff)<<8) | \
                  ((((u_int)(y))&0xff00)>>8)))

// 	get the global header.  Return bytes_received:
// 	< 0 : error
// 	= 0 : socket is closed, EOF
// 	< sizeof(sf_pkthdr) : error
// 	= sizeof(sf_pkthdr) : OK
static int  zpot_get_global_header(int socket_fd, pcap_file_header & global_hdr, bool & swapped)
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

	// should have gotten a full header	
	if (bytes_received < (int) sizeof(global_hdr)) 
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: ONLY got %x bytes",
				bytes_received);
		return -1;
	}

	// check if we support the pcap file type, or have swap issues 
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: magic is %x",         
			global_hdr.magic);
	switch (global_hdr.magic) {
	case 0xa1b2c3d4:
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: no endian swapping");
		swapped = false;
		break;

	case 0xd4c3b2a1:
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: endian swapping enabled");
		swapped = true;
		break;

	default:
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_global_hdr: magic number %d not supported",
			global_hdr.magic);
		return -1;
	}

	// if so, swap the fields
	if (swapped)
	{
		global_hdr.version_major = SWAPSHORT(global_hdr.version_major);
		global_hdr.version_minor = SWAPSHORT(global_hdr.version_minor);
		global_hdr.thiszone      = SWAPLONG(global_hdr.thiszone);
		global_hdr.sigfigs       = SWAPLONG(global_hdr.sigfigs);
		global_hdr.snaplen       = SWAPLONG(global_hdr.snaplen);
		global_hdr.linktype      = SWAPLONG(global_hdr.linktype);
	}

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

//	get the server DNS name and port number.  -1 means error, 0 OK
static int zpot_get_server_name_and_port(const std::string& path, std::string &server_name, int * port)
{
	// find the DNS name and port of server
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_server_name_and_port: path is %s", 
			path.c_str());
	size_t colon_pos = path.find(':');
	if (colon_pos == std::string::npos) 
	{
		return -1;
	}

	// Extract the DNS name and port number as separate strings
	server_name = path.substr(0, colon_pos);
	std::string port_str = path.substr(colon_pos + 1);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_server_name_and_port: server_name is %s", 
			server_name.c_str());
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_server_name_and_port: port_str is %s",  
			port_str.c_str());

	// Convert the port number string to an integer
	int port_number = std::stoi(port_str);
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_server_name_and_port: port_number is %d", 
			port_number );
	*port = port_number;
	return 0;
}

//	convert DNS name to IP address.
//	return 0 if OK, < 0 if not.
static int zpot_resolve_server_name(std::string server_name, std::string &server_ip)
{
	struct addrinfo hints, *res;
        int status;
        char ipstr[INET6_ADDRSTRLEN];

	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_resolve_server_name: entry");

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(server_name.c_str(), NULL, &hints, &res)) != 0) 
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, 
			"zpot_resolve_server_name: getaddrinfo %s",
			gai_strerror(status));
		return -1;
	}

	// take the first IP address we find
	for (struct addrinfo *p = res; p != NULL; p = p->ai_next) 
	{
		void *addr;

		PLUGIN_DBG_LOG(PcapOverTcpFoo, 
				"zpot_resolve_server_name: trying --");
		// get pointer to the address itself,
		// different fields in IPv4 and IPv6:
		if (p->ai_family == AF_INET) { // IPv4
		    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
		    addr = &(ipv4->sin_addr);
		} else { // IPv6
		    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
		    addr = &(ipv6->sin6_addr);
		}

		// convert IP to a string 
		if (inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr) == 0)
		{
			PLUGIN_DBG_LOG(PcapOverTcpFoo, 
				"zpot_resolve_server_name: inet_ntop: %s",
				gai_strerror(status));
			return -1;
		}

		PLUGIN_DBG_LOG(PcapOverTcpFoo, 
				"zpot_resolve_server_name: IP is %s", ipstr);	
		server_ip = ipstr;
		break;
	}

	freeaddrinfo(res); // free the linked list
			 
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_resolve_server_name: exit");
	return 0;
}

//	connect to the server.  
//	-1 is an error, 0 is OK
static int zpot_connect_to_server_ip(int socket_fd, std::string server_ip, int port_number)
{
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_connect_to_server_ip: Connecting... ");
	// setup server_addr for connect
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
	server_addr.sin_port = htons(port_number);

	int delay = 1;
	int rv;
	// Connect to the server
	do {
		// attempt to connect
		rv = connect(socket_fd, reinterpret_cast<sockaddr*>(&server_addr), 
			sizeof(server_addr));
		// if failure is ECONNREFUSED...
		if (rv == -1) 
		{
			// sleep, then try again
			PLUGIN_DBG_LOG(PcapOverTcpFoo, 
					"zpot_connect_to_server_ip: error %d (%s)",
					delay, strerror(errno));
			sleep(delay);
			delay += delay;
		}
	} while ((delay < 16) && (rv == -1));

	if ( rv < 0 ) 
	{
		// didn't make it
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_connect_to_server_ip: connect failed ");
		return -1;
	}
	PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_connect_to_server_ip: Connected ");

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
static int zpot_get_packet_header(int socket_fd, pcap_pkthdr & current_hdr, bool swapped)
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
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: errno is %d (%s)",
				errno, strerror(errno));
		return -1;
	}

	// check for EOF
	if (bytes_received == 0)
	{
		return 0;
	}

	// should have received the full header
	if (bytes_received != sizeof(sf_pkthdr))
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: ONLY got %x bytes",
				bytes_received);
		return -1;
	}

	// check if we need to swap endianness
	if (swapped) 
	{
		// go ahead and swap 
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_header: swapping endianness");
		sf_pkthdr.ts.tv_sec =  SWAPLONG(sf_pkthdr.ts.tv_sec);
		sf_pkthdr.ts.tv_usec = SWAPLONG(sf_pkthdr.ts.tv_usec);
		sf_pkthdr.len =        SWAPLONG(sf_pkthdr.len);
		sf_pkthdr.caplen =     SWAPLONG(sf_pkthdr.caplen);
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
		"zpot_get_packet_body: bufsize %d is smaller than bytes_expected %d",
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

	// check that we got what we expected.  Warning or Error?
	if (bytes_received != bytes_expected)
	{
		PLUGIN_DBG_LOG(PcapOverTcpFoo, "zpot_get_packet_body: ONLY %d bytes_received",
				bytes_received);
	}
	return bytes_received;
}


