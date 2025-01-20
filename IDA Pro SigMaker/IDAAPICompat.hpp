#include "Plugin.h"

// IDA SDK backwards compatibility wrappers
#define IDA_9_VERSION 900

/*
inline const char* compat_inf_get_procname( ) {
#if IDP_INTERFACE_VERSION >= IDA_9_VERSION // IDA 9
	return inf_get_procname( ).c_str( );
#else // IDA 8
	return inf.procname;
#endif
}*/

inline ea_t compat_inf_get_min_ea( ) {
#if IDP_INTERFACE_VERSION >= IDA_9_VERSION // IDA 9
	return inf_get_min_ea( );
#else // IDA 8
	return inf.min_ea;
#endif
}

inline ea_t compat_inf_get_max_ea( ) {
#if IDP_INTERFACE_VERSION >= IDA_9_VERSION // IDA 9
	return inf_get_max_ea( );
#else // IDA 8
	return inf.max_ea;
#endif
}

inline ea_t compat_bin_search( ea_t start_ea, ea_t end_ea, const compiled_binpat_vec_t& data, int flags ) {
#if IDP_INTERFACE_VERSION >= 900 // IDA 9
#ifdef __SDK_BETA__ // IDA 9 Beta
	return bin_search3( start_ea, end_ea, data, flags );
#else // IDA 9 SP1
	return bin_search( start_ea, end_ea, data, flags );
#endif
#else // IDA 8
	return bin_search2( start_ea, end_ea, data, flags );
#endif
}
