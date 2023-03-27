import ZeekControl.plugin

class PcapOverTcp(ZeekControl.plugin.Plugin):
	def __init__(self):
		super(PcapOverTcp, self).__init__(apiversion=1)

	def name(self):
		return "pcapovertcp"

	def pluginVersion(self):
		return 1

	def init(self):
		# Only use the plugin if there is a worker using PcapOverTcp for load balancing.
		for nn in self.nodes():
			if nn.type == "worker" and nn.interface.startswith("pcapovertcp::") and nn.lb_procs:
				return True

		return False

	def nodeKeys(self):
		return ["fanout_id", "fanout_mode", "buffer_size"]

	def zeekctl_config(self):
		script = ""

		# Add custom configuration values per worker.
		for nn in self.nodes():
			if nn.type != "worker" or not nn.lb_procs:
				continue

			params = ""

			if nn.pcapovertcp_fanout_id:
				params += "\n  redef PcapOverTcp::fanout_id = %s;" % nn.pcapovertcp_fanout_id
			if nn.pcapovertcp_fanout_mode:
				params += "\n  redef PcapOverTcp::fanout_mode = %s;" % nn.pcapovertcp_fanout_mode
			if nn.pcapovertcp_buffer_size:
				params += "\n  redef PcapOverTcp::buffer_size = %s;" % nn.pcapovertcp_buffer_size

			if params:
				script += "\n@if( peer_description == \"%s\" ) %s\n@endif" % (nn.name, params)

		return script
