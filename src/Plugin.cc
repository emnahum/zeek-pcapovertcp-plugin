
#include "Plugin.h"
#include "PcapOverTcp.h"
#include "zeek/iosource/Component.h"

namespace plugin::Zeek_PcapOverTcp { Plugin plugin; }

using namespace plugin::Zeek_PcapOverTcp;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::zeek::iosource::PktSrcComponent("PcapOverTcpReader", "pcapovertcp", ::zeek::iosource::PktSrcComponent::LIVE, ::zeek::iosource::pktsrc::PcapOverTcpSource::InstantiatePcapOverTcp));

	zeek::plugin::Configuration config;
	config.name = "Zeek::PcapOverTcp";
	config.description = "Packet acquisition via PCAP over TCP";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
