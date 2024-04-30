/* Standard includes. */
#include <stdint.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_DNS.h"
#include "FreeRTOS_DNS_Parser.h"
#include "NetworkBufferManagement.h"
#include "NetworkInterface.h"
#include "IPTraceMacroDefaults.h"

#include "cbmc.h"
#include "../../utility/memory_assignments.c"

/****************************************************************
* Signature of function under test
****************************************************************/

uint32_t parseDNSAnswer( ParseSet_t * pxSet,
                         struct freertos_addrinfo ** ppxAddressInfo,
                         size_t * uxBytesRead );

uint16_t usChar2u16( const uint8_t * pucPtr )
{
    __CPROVER_assert( __CPROVER_r_ok( pucPtr, 2 ), "must be 2 bytes legal address to read" );
}

struct freertos_addrinfo * pxNew_AddrInfo( const char * pcName,
                                           BaseType_t xFamily,
                                           const uint8_t * pucAddress )
{
    struct freertos_addrinfo *pxAddrinfo = safeMalloc( sizeof( struct freertos_addrinfo ) );
    __CPROVER_assert( ( xFamily == FREERTOS_AF_INET6 && __CPROVER_w_ok( pucAddress, 16 ) ) ||
                      ( xFamily == FREERTOS_AF_INET && __CPROVER_w_ok( pucAddress, 4 ) ), "address must be available to store memory based on family" );

    return pxAddrinfo;
}

BaseType_t FreeRTOS_dns_update( const char * pcName,
                                IPv46_Address_t * pxIP,
                                uint32_t ulTTL,
                                BaseType_t xLookUp,
                                struct freertos_addrinfo ** ppxAddressInfo )
{
    BaseType_t result;

    return result;
}

const char * FreeRTOS_inet_ntop( BaseType_t xAddressFamily,
                                 const void * pvSource,
                                 char * pcDestination,
                                 socklen_t uxSize )
{
    __CPROVER_assert( __CPROVER_r_ok( pcDestination, uxSize ), "input buffer must be available" );

    __CPROVER_assert( ( xAddressFamily == FREERTOS_AF_INET6 && __CPROVER_r_ok( pvSource, 16 ) ) ||
                      ( xAddressFamily == FREERTOS_AF_INET && __CPROVER_r_ok( pvSource, 4 ) ),
                      "input address must be available" );

    __CPROVER_assert( __CPROVER_w_ok( pcDestination, uxSize ),
                      "input address must be available" );
}

size_t DNS_SkipNameField( const uint8_t * pucByte,
                          size_t uxLength )
{
    size_t result;

    __CPROVER_assert( __CPROVER_r_ok( pucByte, uxLength ), "input buffer must be accessable" );
    __CPROVER_assume( result <= uxLength );

    return result;
}

/****************************************************************
* Proof of prvParseDNSReply
****************************************************************/

void harness()
{
    struct freertos_addrinfo *pxAddressInfo;
    uint8_t *pPayloadBuffer;
    size_t uxPayloadBufferLength;
    size_t uxBytesRead;
    ParseSet_t xSet;

    __CPROVER_assert( TEST_PACKET_SIZE < CBMC_MAX_OBJECT_SIZE,
                      "TEST_PACKET_SIZE < CBMC_MAX_OBJECT_SIZE" );

    __CPROVER_assume( uxPayloadBufferLength < CBMC_MAX_OBJECT_SIZE );
    __CPROVER_assume( uxPayloadBufferLength <= TEST_PACKET_SIZE );

    xSet.pucByte = safeMalloc( uxPayloadBufferLength );
    xSet.uxSourceBytesRemaining = uxPayloadBufferLength;
    __CPROVER_assume( xSet.pucByte != NULL );

    xSet.pxDNSMessageHeader = safeMalloc( sizeof( DNSMessage_t ) );
    __CPROVER_assume( xSet.pxDNSMessageHeader != NULL );
    xSet.ppxLastAddress = &( xSet.pxLastAddress );

    uint32_t index = parseDNSAnswer( &xSet,
                                     &pxAddressInfo,
                                     &uxBytesRead );
}
