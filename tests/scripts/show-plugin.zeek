# @TEST-EXEC: zeek -NN Zeek::PcapOverTcp |sed -e 's/version.*)/version)/g' > output
# @TEST-EXEC: btest-diff output
