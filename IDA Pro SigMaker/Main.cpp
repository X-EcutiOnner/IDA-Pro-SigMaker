#include "Main.h"
#include "Utils.h"
#include "SignatureUtils.h"
#include "IDAAPICompat.hpp"

#define QIS_SIGNATURE_USE_AVX2 1 
#include <qis/signature.hpp>

uint32_t PROCESSOR_ARCH;

bool USE_QIS_SIGNATURE = false;
bool WILDCARD_OPTIMIZED_INSTRUCTION = true;
size_t PRINT_TOP_X = 5;
size_t MAX_SINGLE_SIGNATURE_LENGTH = 1000;
size_t MAX_XREF_SIGNATURE_LENGTH = 250;

std::vector<uint8_t> FILE_BUFFER = {};

static uint32_t WildcardableOperandTypeBitmask = 0;

static bool GetOperandOffset( const insn_t& instruction, uint8_t* operandOffset, uint8_t* operandLength, uint32_t operandTypeBitmask ) {

	// Iterate all operands
	for( const auto& op : instruction.ops ) {
		// Skip if we have no operand
		if( op.type == o_void ) {
			continue;
		}

		// Apply operand bitmask filter
		if( ( BIT( op.type ) & operandTypeBitmask ) == 0 ) {
			continue;
		}

		*operandOffset = op.offb;

		bool isOptimizedInstr = false;
		// Find operand length based on processor arch
		switch( PROCESSOR_ARCH ) {
		case PLFM_ARM: // ARM, since operands are at the beginning
		{
			// This is somewhat of a hack because IDA api does not provide more info for ARM
			// I always assume the operand is 3 bytes long with 1 byte operator
			if( instruction.size == 4 ) {
				*operandLength = 3;
			}
			// I saw some ADRL instruction having 8 bytes
			if( instruction.size == 8 ) {
				*operandLength = 7;
			}
			break;
		}
		case PLFM_386: // METAPC
		{
			// Usually the instruction is optimized and the operand is part of the operator and thus can't be described by offb
			if( op.offb == 0 ) {
				isOptimizedInstr = true;
			}
		}
		default: // Everything else
			*operandLength = instruction.size - op.offb;
			break;
		}

		if( isOptimizedInstr && !WILDCARD_OPTIMIZED_INSTRUCTION ) {
	 		continue;
		}

		return true;
	}
	return false;
}

// Credit: belmeopmenieuwesim @ https://github.com/belmeopmenieuwesim/IDA-Pro-SigMaker/blob/697bebd3ecd71cb8af21ab10fb5006af8676252f/IDA%20Pro%20SigMaker/Main.cpp#L204C1-L227C52
static std::vector<uint8_t> ReadSegmentsToBuffer( ) {
	std::vector<uint8_t> buffer;

	// Iterate over all segments
	for( int i = 0; i < get_segm_qty( ); ++i ) {
		auto seg = getnseg( i );
		if( !seg ) {
			continue;
		}

		auto ea = buffer.empty( ) ? compat_inf_get_min_ea( ) : seg->start_ea;
		size_t size = seg->end_ea - ea;

		// Resize the buffer to accommodate the segment data
		auto current_size = buffer.size( );
		buffer.resize( current_size + size );

		// Read the segment data into the buffer
		get_bytes( &buffer[current_size], size, ea );
	}

	return buffer;
}
//

static std::string IdaToQisSignatureStr( std::string_view idaSignature ) {
	// Qis signature uses double quotes
	return std::regex_replace( idaSignature.data( ), std::regex( "\\?" ), "??" );
}

static std::vector<ea_t> FindSignatureOccurencesQis( std::string_view idaSignature, bool skipMoreThanOne = false ) {

	// Load file into our own buffer, since we can't get a direct pointer to the mapped binary
	if( FILE_BUFFER.empty( ) ) {
		show_wait_box( "Please stand by, copying segments..." );
		FILE_BUFFER = ReadSegmentsToBuffer( );
		hide_wait_box( );
	}

	// Create qis signature from ida signature string
	const qis::signature qisSignature( IdaToQisSignatureStr( idaSignature ) );

	// Search for occurences
	std::vector<ea_t> results;
	auto currentPtr = FILE_BUFFER.data( );
	while( true ) {
		auto occurence = qis::scan( currentPtr, FILE_BUFFER.size( ) - ( currentPtr - FILE_BUFFER.data( ) ), qisSignature );

		// Signature not found anymore
		if( occurence == qis::npos ) {
			break;
		}

		//  In case we only care about uniqueness, return after more than one result
		if( skipMoreThanOne && results.size( ) > 1 ) {
			break;
		}

		auto fileOffset = ( ( currentPtr - FILE_BUFFER.data( ) ) + occurence );

		results.push_back( compat_inf_get_min_ea( ) + fileOffset );

		currentPtr = FILE_BUFFER.data( ) + fileOffset + 1;
	}
	return results;
}

static std::vector<ea_t> FindSignatureOccurences( std::string_view idaSignature, bool skipMoreThanOne = false ) {

	if( USE_QIS_SIGNATURE ) {
		return FindSignatureOccurencesQis( idaSignature, skipMoreThanOne );
	}

	// Convert signature string to searchable struct
	compiled_binpat_vec_t binaryPattern;
	parse_binpat_str( &binaryPattern, compat_inf_get_min_ea( ), idaSignature.data( ), 16 );

	// Search for occurences
	std::vector<ea_t> results;
	auto ea = compat_inf_get_min_ea( );
	while( true ) {
		auto occurence = compat_bin_search( ea, compat_inf_get_max_ea( ), binaryPattern, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD );

		// Signature not found anymore
		if( occurence == BADADDR ) {
			break;
		}

		//  In case we only care about uniqueness, return after more than one result
		if( skipMoreThanOne && results.size( ) > 1 ) {
			break;
		}

		results.push_back( occurence );

		ea = occurence + 1;
	}
	return results;
}

static bool IsSignatureUnique( std::string_view idaSignature ) {
	return FindSignatureOccurences( idaSignature, true ).size( ) == 1;
}

static std::expected<Signature, std::string> GenerateUniqueSignatureForEA( ea_t ea, bool wildcardOperands, bool continueOutsideOfFunction, uint32_t operandTypeBitmask, size_t maxSignatureLength, bool askLongerSignature = true ) {
	if( ea == BADADDR ) {
		return std::unexpected( "Invalid address" );
	}

	if( !is_code( get_flags( ea ) ) ) {
		return std::unexpected( "Can not create code signature for data" );
	}

	Signature signature;
	size_t sigPartLength = 0;

	auto currentFunction = get_func( ea );

	auto currentAddress = ea;
	while( true ) {
		// Handle IDA "cancel" event
		if( user_cancelled( ) ) {
			return std::unexpected( "Aborted" );
		}

		insn_t instruction;
		auto currentInstructionLength = decode_insn( &instruction, currentAddress );
		if( currentInstructionLength <= 0 ) {
			if( signature.empty( ) ) {
				return std::unexpected( "Failed to decode first instruction" );
			}

			msg( "Signature reached end of executable code @ %I64X\n", currentAddress );
			auto signatureString = BuildIDASignatureString( signature );
			msg( "NOT UNIQUE Signature for %I64X: %s\n", ea, signatureString.c_str( ) );
			return std::unexpected( "Signature not unique" );
		}

		// Length check in case the signature becomes too long
		if( sigPartLength > maxSignatureLength ) {
			if( askLongerSignature ) {
				auto result = ask_yn( ASKBTN_YES, "Signature is already at %llu bytes. Continue?", signature.size( ) );
				if( result == 1 ) { // Yes 
					sigPartLength = 0;
				}
				else if( result == 0 ) { // No
					// Print the signature we have so far, even though its not unique
					auto signatureString = BuildIDASignatureString( signature );
					msg( "NOT UNIQUE Signature for %I64X: %s\n", ea, signatureString.c_str( ) );
					return std::unexpected( "Signature not unique" );
				}
				else { // Cancel
					return std::unexpected( "Aborted" );
				}
			}
			else {
				return std::unexpected( "Signature exceeded maximum length" );
			}
		}
		sigPartLength += currentInstructionLength;

		// Check current instruction, add its bytes to the signature accordingly
		uint8_t operandOffset = 0, operandLength = 0;
		if( wildcardOperands && GetOperandOffset( instruction, &operandOffset, &operandLength, operandTypeBitmask ) && operandLength > 0 ) {
			// Add opcodes
			AddBytesToSignature( signature, currentAddress, operandOffset, false );
			// Wildcards for operands
			AddBytesToSignature( signature, currentAddress + operandOffset, operandLength, true );
			// If the operand is on the "left side", add the operator from the "right side"
			if( operandOffset == 0 ) {
				AddBytesToSignature( signature, currentAddress + operandLength, currentInstructionLength - operandLength, false );
			}
		}
		else {
			// No operand, add all bytes
			AddBytesToSignature( signature, currentAddress, currentInstructionLength, false );
		}

		auto currentSig = BuildIDASignatureString( signature );
		if( IsSignatureUnique( currentSig ) ) {
			// Remove wildcards at end for output
			TrimSignature( signature );

			// Return the signature we generated
			return signature;
		}
		currentAddress += currentInstructionLength;

		// Break if we leave function
		if( !continueOutsideOfFunction && currentFunction && get_func( currentAddress ) != currentFunction ) {
			return std::unexpected( "Signature left function scope" );
		}

	}
	return std::unexpected( "Unknown" );
}

// Function for code selection
static std::expected<Signature, std::string> GenerateSignatureForEARange( ea_t eaStart, ea_t eaEnd, bool wildcardOperands, uint32_t operandTypeBitmask ) {
	if( eaStart == BADADDR || eaEnd == BADADDR ) {
		return std::unexpected( "Invalid address" );
	}

	Signature signature;
	size_t sigPartLength = 0;

	// Copy data section, no wildcards
	if( !is_code( get_flags( eaStart ) ) ) {
		AddBytesToSignature( signature, eaStart, eaEnd - eaStart, false );
		return signature;
	}

	auto currentAddress = eaStart;
	while( true ) {
		// Handle IDA "cancel" event
		if( user_cancelled( ) ) {
			return std::unexpected( "Aborted" );
		}

		insn_t instruction;
		auto currentInstructionLength = decode_insn( &instruction, currentAddress );
		if( currentInstructionLength <= 0 ) {
			if( signature.empty( ) ) {
				return std::unexpected( "Failed to decode first instruction" );
			}

			msg( "Signature reached end of executable code @ %I64X\n", currentAddress );
			// If we have some bytes left, add them
			if( currentAddress < eaEnd ) {
				AddBytesToSignature( signature, currentAddress, eaEnd - currentAddress, false );
			}
			TrimSignature( signature );
			return signature;
		}

		sigPartLength += currentInstructionLength;

		uint8_t operandOffset = 0, operandLength = 0;
		if( wildcardOperands && GetOperandOffset( instruction, &operandOffset, &operandLength, operandTypeBitmask ) && operandLength > 0 ) {
			// Add opcodes
			AddBytesToSignature( signature, currentAddress, operandOffset, false );
			// Wildcards for operands
			AddBytesToSignature( signature, currentAddress + operandOffset, operandLength, true );
			// If the operand is on the "left side", add the operator from the "right side"
			if( operandOffset == 0 ) {
				AddBytesToSignature( signature, currentAddress + operandLength, currentInstructionLength - operandLength, false );
			}
		}
		else {
			// No operand, add all bytes
			AddBytesToSignature( signature, currentAddress, currentInstructionLength, false );
		}
		currentAddress += currentInstructionLength;

		if( currentAddress >= eaEnd ) {

			TrimSignature( signature );
			return signature;
		}
	}
	return std::unexpected( "Unknown" );
}

static void PrintSignatureForEA( const std::expected<Signature, std::string>& signature, ea_t ea, SignatureType sigOutputType ) {
	if( !signature.has_value( ) ) {
		msg( "Error: %s\n", signature.error( ).c_str( ) );
		return;
	}
	const auto signatureStr = FormatSignature( signature.value( ), sigOutputType );
	msg( "Signature for %I64X: %s\n", ea, signatureStr.c_str( ) );
	if( !SetClipboardText( signatureStr ) ) {
		msg( "Failed to copy to clipboard!" );
	}
}

static void FindXRefs( ea_t ea, bool wildcardOperands, bool continueOutsideOfFunction, std::vector<std::tuple<ea_t, Signature>>& xrefSignatures, size_t maxSignatureLength, uint32_t operandTypeBitmask ) {
	xrefblk_t xref{};

	// Count code xrefs
	size_t xrefCount = 0;
	for( auto xref_ok = xref.first_to( ea, XREF_FAR ); xref_ok; xref_ok = xref.next_to( ) ) {
		if( !is_code( get_flags( xref.from ) ) ) {
			continue;
		}
		++xrefCount;
	}

	size_t shortestSignatureLength = maxSignatureLength + 1;

	size_t i = 0;
	for( auto xref_ok = xref.first_to( ea, XREF_FAR ); xref_ok; xref_ok = xref.next_to( ), ++i ) {

		// Instantly abort
		if( user_cancelled( ) ) {
			break;
		}

		// Skip data refs, xref.iscode is not what we want though
		if( !is_code( get_flags( xref.from ) ) ) {
			continue;
		}

		replace_wait_box( "Processing xref %llu of %llu (%0.1f%%)...\n\nSuitable Signatures: %llu\nShortest Signature: %llu Bytes", i + 1, xrefCount, ( static_cast<float>( i ) / xrefCount ) * 100.0f, xrefSignatures.size( ), ( shortestSignatureLength <= maxSignatureLength ? shortestSignatureLength : 0 ) );

		// Genreate signature for xref
		auto signature = GenerateUniqueSignatureForEA( xref.from, wildcardOperands, continueOutsideOfFunction, operandTypeBitmask, maxSignatureLength, false );
		if( !signature.has_value( ) ) {
			continue;
		}

		// Update for statistics
		if( signature.value( ).size( ) < shortestSignatureLength ) {
			shortestSignatureLength = signature.value( ).size( );
		}

		xrefSignatures.push_back( std::make_pair( xref.from, signature.value( ) ) );
	}

	// Sort signatures by length
	std::ranges::sort( xrefSignatures, []( const auto& a, const auto& b ) -> bool { return std::get<1>( a ).size( ) < std::get<1>( b ).size( ); } );
}

static void PrintXRefSignaturesForEA( ea_t ea, const std::vector<std::tuple<ea_t, Signature>>& xrefSignatures, SignatureType sigType, size_t topCount ) {
	if( xrefSignatures.empty( ) ) {
		msg( "No XREFs have been found for your address\n" );
		return;
	}

	auto topLength = std::min( topCount, xrefSignatures.size( ) );
	msg( "Top %llu Signatures out of %llu suitable xrefs for %I64X:\n", topLength, xrefSignatures.size( ), ea );
	for( size_t i = 0; i < topLength; i++ ) {
		const auto& [originAddress, signature] = xrefSignatures[i];
		const auto signatureStr = FormatSignature( signature, sigType );
		msg( "XREF Signature #%i @ %I64X: %s\n", i + 1, originAddress, signatureStr.c_str( ) );

		// Copy first signature only
		if( i == 0 ) {
			SetClipboardText( signatureStr );
		}
	}
}

static void PrintSelectedCode( ea_t start, ea_t end, SignatureType sigType, bool wildcardOperands, uint32_t operandBitmask ) {
	const auto selectionSize = end - start;
	// Create signature of fixed size from selection

	auto signature = GenerateSignatureForEARange( start, end, wildcardOperands, operandBitmask );
	if( !signature.has_value( ) ) {
		msg( "Error: %s\n", signature.error( ).c_str( ) );
		return;
	}

	const auto signatureStr = FormatSignature( signature.value( ), sigType );
	msg( "Code for %I64X-%I64X: %s\n", start, end, signatureStr.c_str( ) );
	SetClipboardText( signatureStr );
}

static void SearchSignatureString( std::string input ) {
	// Try to figure out what signature type is used
	// We will convert it to IDA style
	std::string convertedSignatureString;

	std::string stringMask;

	// Try to detect a string mask like "xx????xx?xx"
	// Assume string mask always starts with x, and we don't just have one byte
	std::smatch match;
	if( std::regex_search( input, match, std::regex( R"(x(?:x|\?)+)" ) ) ) {
		stringMask = match[0].str( );
	}
	// Try to find binary style bitmask like "0b101110" and convert it to a string mask
	else if( std::regex_search( input, match, std::regex( R"(0b(?:[0,1])+)" ) ) ) {
		auto bits = match[0].str( ).substr( 2 );
		std::string reversedBits( bits.rbegin( ), bits.rend( ) );
		for( const auto& b : reversedBits ) {
			stringMask += ( b == '1' ? 'x' : '?' );
		}
	}

	if( !stringMask.empty( ) ) {
		// Since we have a mask, search for the bytes

		std::vector<std::string> rawByteStrings;
		// Search for \x00\x11\x22 type arrays
		if( GetRegexMatches( input, std::regex( R"(\\x(?:[0-9A-F]{2}))", std::regex_constants::icase ), rawByteStrings ) && rawByteStrings.size( ) == stringMask.length( ) ) {
			Signature convertedSignature;
			for( size_t i = 0; const auto & m : rawByteStrings ) {
				SignatureByte b{ std::stoi( m.substr( 2 ), nullptr, 16 ), stringMask[i++] == '?' };
				convertedSignature.push_back( b );
			}
			convertedSignatureString = BuildIDASignatureString( convertedSignature );
		}
		// Search for 0x00, 0x11, 0x22 type arrays
		else if( GetRegexMatches( input, std::regex( R"((?:0x(?:[0-9A-F]{2}))+)", std::regex_constants::icase ), rawByteStrings ) && rawByteStrings.size( ) == stringMask.length( ) ) {
			Signature convertedSignature;
			for( size_t i = 0; const auto & m : rawByteStrings ) {
				SignatureByte b{ std::stoi( m.substr( 2 ), nullptr, 16 ), stringMask[i++] == '?' };
				convertedSignature.push_back( b );
			}
			convertedSignatureString = BuildIDASignatureString( convertedSignature );
		}
		else {
			msg( "Detected mask \"%s\" but failed to match corresponding bytes\n", stringMask.c_str( ) );
		}
	}
	else {
		// We did not find a specific mask, so try formats with included wildcards 

		// Remove braces in case you have makers in your IDA style signature 
		input = std::regex_replace( input, std::regex( R"([\)\(\[\]]+)" ), "" );

		// Remove whitespace at beginning, questionmarks and spaces at the end, and add one space for the following step
		input = std::regex_replace( input, std::regex( "^\\s+" ), "" );
		input = std::regex_replace( input, std::regex( "[? ]+$" ), "" ) + " ";

		// Replace double question marks with single ones to convert x64Dbg style to IDA style
		// We need spaces between signature bytes, because we can not recognize if a signature uses one or two question marks per wildcard
		input = std::regex_replace( input, std::regex( R"(\?\? )" ), "? " );

		// Direct match for IDA type signature
		if( std::regex_match( input, std::regex( R"((?:(?:[0-9A-F]{2}\s+)|(?:\?\s+))+)", std::regex_constants::icase ) ) ) {
			// Just use it
			convertedSignatureString = input;
		}
		else {
			// Just try the other formats without wildcards

			std::vector<std::string> rawByteStrings;
			// Search for \x00\x11\x22 type arrays

			if( GetRegexMatches( input, std::regex( R"(\\x(?:[0-9A-F]{2}))", std::regex_constants::icase ), rawByteStrings ) && rawByteStrings.size( ) > 1 ) {
				Signature convertedSignature;
				for( size_t i = 0; const auto & m : rawByteStrings ) {
					SignatureByte b{ std::stoi( m.substr( 2 ), nullptr, 16 ), false };
					convertedSignature.push_back( b );
				}
				convertedSignatureString = BuildIDASignatureString( convertedSignature );
			}
			// Search for 0x00, 0x11, 0x22 type arrays
			else if( GetRegexMatches( input, std::regex( R"((?:0x(?:[0-9A-F]{2}))+)", std::regex_constants::icase ), rawByteStrings ) && rawByteStrings.size( ) > 1 ) {
				Signature convertedSignature;
				for( size_t i = 0; const auto & m : rawByteStrings ) {
					SignatureByte b{ std::stoi( m.substr( 2 ), nullptr, 16 ), false };
					convertedSignature.push_back( b );
				}
				convertedSignatureString = BuildIDASignatureString( convertedSignature );
			}
			else {
				msg( "Failed to match signature format\n" );
			}
		}
	}

	if( convertedSignatureString.empty( ) ) {
		msg( "Unrecognized signature type\n" );
		return;
	}

	// Remove space from the end
	convertedSignatureString = std::regex_replace( convertedSignatureString, std::regex( "[? ]+$" ), "" );

	// Print results
	msg( "Results for %s:\n", convertedSignatureString.c_str( ) );
	auto signatureMatches = FindSignatureOccurences( convertedSignatureString );
	if( signatureMatches.empty( ) ) {
		msg( "Signature does not match!\n" );
		return;
	}
	for( const auto& ea : signatureMatches ) {
		msg( "Match @ %I64X\n", ea );
	}
}

static void ConfigureOperandWildcardBitmask( ) {

	std::stringstream formString;
	const char baseOptions[] =
		"STARTITEM 0\n"                                                         // TabStop
		"Wildcardable Operands\n"                                               // Title
		"Select operand types that should be wildcarded:\n"                     // Header
		"<General Register (al,ax,es,ds...):C>\n"                               // Radio Button 0
		"<Direct Memory Reference  (DATA):C>\n"                                 // Radio Button 1
		"<Memory Ref [Base Reg + Index Reg]:C>\n"                               // Radio Button 2
		"<Memory Ref [Base Reg + Index Reg + Displacement]:C>\n"                // Radio Button 3
		"<Immediate Value:C>\n"                                                 // Radio Button 4
		"<Immediate Far Address  (CODE):C>\n"                                   // Radio Button 5
		"<Immediate Near Address (CODE):C>";                                    // Radio Button 6
	formString << baseOptions;

	// Processor specific wildcards
	switch( PROCESSOR_ARCH ) {
	case PLFM_386:
		formString << "\n";
		formString << "<Trace Register:C>\n";
		formString << "<Debug Register:C>\n";
		formString << "<Control Register:C>\n";
		formString << "<Floating Point Register:C>\n";
		formString << "<MMX Register:C>\n";
		formString << "<XMM Register:C>\n";
		formString << "<YMM Register:C>\n";
		formString << "<ZMM Register:C>\n";
		formString << "<Opmask Register:C>>\n";
		break;
	case PLFM_ARM:
		formString << "\n";
		formString << "<(Unused):C>\n";
		formString << "<Register list (for LDM/STM):C>\n";
		formString << "<Coprocessor register list (for CDP):C>\n";
		formString << "<Coprocessor register (for LDC/STC):C>\n";
		formString << "<Floating point register list:C>\n";
		formString << "<Arbitrary text stored in the operand:C>\n";
		formString << "<ARM condition as an operand:C>>\n";
		break;
	case PLFM_PPC:
		formString << "\n";
		formString << "<Special purpose register:C>\n";
		formString << "<Two FPRs:C>\n";
		formString << "<SH & MB & ME:C>\n";
		formString << "<crfield:C>\n";
		formString << "<crbit:C>\n";
		formString << "<Device control register:C>>\n";
		break;
	default:
		formString << ">\n";
		break;
	}

	// Shift by one because we skip o_void
	uint32_t options = WildcardableOperandTypeBitmask >> 1;
	if( ask_form( formString.str( ).c_str( ), &options ) ) {
		WildcardableOperandTypeBitmask = ( options << 1 );
	}
}

static void ConfigureOptions( ) {
	const char format[] =
		"STARTITEM 0\n"                                                         // TabStop
		"Options\n"                                                             // Title
		"<#Print top X shortest signatures when generating xref signatures#Print top X XREF signatures     :u::5::>\n"                           // Number 0
		"<#Stop after reaching X bytes when generating a single signature#Maximum single signature length :u::5::>\n"							 // Number 1
		"<#Stop after reaching X bytes when generating xref signatures#Maximum xref signature length   :u::5::>\n";                              // Number 2

	if( ask_form( format, &PRINT_TOP_X, &MAX_SINGLE_SIGNATURE_LENGTH, &MAX_XREF_SIGNATURE_LENGTH ) ) {
	}
}

bool idaapi plugin_ctx_t::run( size_t ) {

	// Check what processor we have
	PROCESSOR_ARCH = get_ph( )->id;

	// Default wildcard setting depending on processor arch
	if( WildcardableOperandTypeBitmask == 0 ) {
		switch( PROCESSOR_ARCH ) {
		case PLFM_386:
			WildcardableOperandTypeBitmask =
				/*BIT( o_reg ) | */ BIT( o_mem ) | BIT( o_phrase ) | BIT( o_displ ) | BIT( o_far ) | BIT( o_near ) | BIT( o_imm ) |
				BIT( o_trreg ) | BIT( o_dbreg ) | BIT( o_crreg ) | BIT( o_fpreg ) | BIT( o_mmxreg ) | BIT( o_xmmreg ) | BIT( o_xmmreg ) | BIT( o_ymmreg ) | BIT( o_zmmreg ) | BIT( o_kreg );
			break;
		case PLFM_ARM:
			WildcardableOperandTypeBitmask =
				BIT( o_mem ) | BIT( o_phrase ) | BIT( o_displ ) | BIT( o_far ) | BIT( o_near ) | BIT( o_imm );
			// BIT( o_reg ) | BIT( o_idpspec1 ) | BIT( o_idpspec2 ) | BIT( o_idpspec3 ) | BIT( o_idpspec4 ) | BIT( o_idpspec5 ) | BIT( o_idpspec5 + 1 );
			// o_reglist, o_creglist, o_creg, o_fpreglist, o_text, o_cond
			break;
		case PLFM_MIPS:
			WildcardableOperandTypeBitmask =
				BIT( o_mem ) | BIT( o_far ) | BIT( o_near );
			break;
		default:
			WildcardableOperandTypeBitmask =
				BIT( o_mem ) | BIT( o_phrase ) | BIT( o_displ ) | BIT( o_far ) | BIT( o_near ) | BIT( o_imm );
		}
	}

	// Check for AVX2, to use qis' signature scanning library for faster signature creation
	if( IsProcessorFeaturePresent( PF_AVX2_INSTRUCTIONS_AVAILABLE ) ) {
		USE_QIS_SIGNATURE = true;
	}

	// Show dialog
	const char menuItems[] =
		"Select action:\n"                                                                                                                                            // Title
		"<#Select an address, and create a code signature for it#Create unique signature for current code address:R>\n"                                               // Radio Button 0
		"<#Select an address or variable, and create code signatures for its references. Will output the shortest 5 signatures#Find shortest XREF signature for current data or code address:R>\n"            // Radio Button 1
		"<#Select 1+ instructions, and copy the bytes using the specified output format#Copy selected code:R>\n"                                                      // Radio Button 2
		"<#Paste any string containing your signature/mask and find matches#Search for a signature:R>>\n"                                                             // Radio Button 3

		"Output format:\n"                                                                                                                                            // Title
		"<#Example - E8 ? ? ? ? 45 33 F6 66 44 89 34 33#IDA Signature:R>\n"                                                                                           // Radio Button 0
		"<#Example - E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33#x64Dbg Signature:R>\n"                                                                                    // Radio Button 1
		"<#Example - \\xE8\\x00\\x00\\x00\\x00\\x45\\x33\\xF6\\x66\\x44\\x89\\x34\\x33 x????xxxxxxxx#C Byte Array String Signature + String mask : R>\n"              // Radio Button 2
		"<#Example - 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33 0b1111111100001#C Bytes Signature + Bitmask:R>>\n"                  // Radio Button 3

		"Quick Options:\n"                                                                                                                                                  // Title
		"<#Enable wildcarding for operands, to improve stability of created signatures#Wildcards for operands:C>\n"                                                   // Checkbox Button 0                                            
		"<#Don't stop signature generation when reaching end of function#Continue when leaving function scope:C>\n"                                                   // Checkbox Button 1
		"<#Wildcard the whole instruction when the operand (usually a register) is encoded into the operator#Wildcard optimized / combined instructions:C>>\n"        // Checkbox Button 2																										  // Checkbox Button 2
		"<#Configure operand types that should be wildcarded#Operand types...:B::::>"                                                                                 // Button 0
		"<#Other options#Options...:B::::>\n";                                                                                                                        // Button 1


	std::stringstream formString;
	formString << "STARTITEM 0\n";
	formString << PLUGIN_NAME " v" PLUGIN_VERSION;    // Title
	if( USE_QIS_SIGNATURE ) {
		formString << " (AVX2)";
	}
	formString << "\n";
	formString << menuItems; // Content

	static short action = 0;
	static short outputFormat = 0;
	static short options = ( 1 << 0 | 0 << 1 | WILDCARD_OPTIMIZED_INSTRUCTION << 2 );

	if( ask_form( formString.str( ).c_str( ), &action, &outputFormat, &options, &ConfigureOperandWildcardBitmask, &ConfigureOptions ) ) {
		const auto wildcardOperands = options & ( 1 << 0 );
		const auto continueOutsideOfFunction = options & ( 1 << 1 );
		WILDCARD_OPTIMIZED_INSTRUCTION = options & ( 1 << 2 );

		const auto sigType = static_cast<SignatureType>( outputFormat );
		switch( action ) {
		case 0:
		{
			// Find unique signature for current address
			const auto ea = get_screen_ea( );

			show_wait_box( "Generating signature..." );

			auto signature = GenerateUniqueSignatureForEA( ea, wildcardOperands, continueOutsideOfFunction, WildcardableOperandTypeBitmask, MAX_SINGLE_SIGNATURE_LENGTH );
			PrintSignatureForEA( signature, ea, sigType );

			hide_wait_box( );
			break;
		}
		case 1:
		{
			// Find XREFs for current selection, generate signatures up to 250 bytes length
			const auto ea = get_screen_ea( );
			std::vector<std::tuple<ea_t, Signature>> xrefSignatures;

			show_wait_box( "Finding references and generating signatures. This can take a while..." );

			FindXRefs( ea, wildcardOperands, continueOutsideOfFunction, xrefSignatures, MAX_XREF_SIGNATURE_LENGTH, WildcardableOperandTypeBitmask );

			// Print top 5 shortest signatures
			PrintXRefSignaturesForEA( ea, xrefSignatures, sigType, PRINT_TOP_X );

			hide_wait_box( );
			break;
		}
		case 2:
		{
			// Print selected code as signature
			ea_t start, end;
			if( read_range_selection( get_current_viewer( ), &start, &end ) ) {
				show_wait_box( "Please stand by..." );

				PrintSelectedCode( start, end, sigType, wildcardOperands, WildcardableOperandTypeBitmask );

				hide_wait_box( );
			}
			else {
				msg( "Select a range to copy the code\n" );
			}
			break;
		}
		case 3:
		{
			// Search for a signature
			qstring inputSignatureQstring;
			if( ask_str( &inputSignatureQstring, HIST_SRCH, "Enter a signature" ) ) {
				show_wait_box( "Searching..." );

				SearchSignatureString( inputSignatureQstring.c_str( ) );

				hide_wait_box( );
			}
			break;
		}
		default:
			break;
		}
	}
	return true;
}
