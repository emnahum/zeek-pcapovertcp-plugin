
#ifndef ZEEK_PLUGIN_ZEEK_PCAP_OVER_TCP
#define ZEEK_PLUGIN_ZEEK_PCAP_OVER_TCP

#include <zeek/plugin/Plugin.h>

namespace plugin::Zeek_PcapOverTcp {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}

#endif
