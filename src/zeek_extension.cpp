#define DUCKDB_EXTENSION_MAIN

#include "zeek_extension.hpp"
#include "zeek_reader.hpp"
#include "duckdb.hpp"

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	loader.RegisterFunction(GetZeekScanFunction());
}

void ZeekExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string ZeekExtension::Name() {
	return "zeek";
}

std::string ZeekExtension::Version() const {
#ifdef EXT_VERSION_ZEEK
	return EXT_VERSION_ZEEK;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(zeek, loader) {
	duckdb::LoadInternal(loader);
}
}
