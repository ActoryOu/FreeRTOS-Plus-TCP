/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "queue.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_TCP_IP.h"
#include "FreeRTOS_Stream_Buffer.h"

/* CBMC includes. */
#include "cbmc.h"
#include "../../utility/memory_assignments.c"

int lIsIPv6Packet;

/* This proof assumes pxTCPSocketLookup and pxGetNetworkBufferWithDescriptor
 * are implemented correctly.
 *
 * It also assumes prvSingleStepTCPHeaderOptions, prvCheckOptions, prvTCPPrepareSend,
 * prvTCPHandleState, prvHandleListen_IPV4 and prvTCPReturnPacket are correct. These functions are
 * proved to be correct separately. */

/* Abstraction of xTaskGetCurrentTaskHandle */
TaskHandle_t xTaskGetCurrentTaskHandle( void )
{
    static int xIsInit = 0;
    static TaskHandle_t pxCurrentTCB;
    TaskHandle_t xRandomTaskHandle; /* not initialized on purpose */

    if( xIsInit == 0 )
    {
        pxCurrentTCB = xRandomTaskHandle;
        xIsInit = 1;
    }

    return pxCurrentTCB;
}

/* Abstraction of prvHandleListen_IPV4 */
FreeRTOS_Socket_t * prvHandleListen_IPV4( FreeRTOS_Socket_t * pxSocket,
                                          NetworkBufferDescriptor_t * pxNetworkBuffer )
{
    FreeRTOS_Socket_t * xRetSocket = ensure_FreeRTOS_Socket_t_is_allocated();

    __CPROVER_assert( !lIsIPv6Packet, "Must not enter here while handling IPv6 packet" );

    if( xRetSocket )
    {
        /* This test case is for IPv4. */
        __CPROVER_assume( xRetSocket->bits.bIsIPv6 == pdFALSE );
    }

    return xRetSocket;
}

/* Abstraction of prvHandleListen_IPV6 */
FreeRTOS_Socket_t * prvHandleListen_IPV6( FreeRTOS_Socket_t * pxSocket,
                                          NetworkBufferDescriptor_t * pxNetworkBuffer )
{
    FreeRTOS_Socket_t * xRetSocket = ensure_FreeRTOS_Socket_t_is_allocated();

    __CPROVER_assert( lIsIPv6Packet, "Must not enter here while handling IPv4 packet" );

    if( xRetSocket )
    {
        /* This test case is for IPv6. */
        __CPROVER_assume( xRetSocket->bits.bIsIPv6 == pdTRUE );
    }

    return xRetSocket;
}

/* Abstraction of pxTCPSocketLookup */
FreeRTOS_Socket_t * pxTCPSocketLookup( uint32_t ulLocalIP,
                                       UBaseType_t uxLocalPort,
                                       IPv46_Address_t xRemoteIP,
                                       UBaseType_t uxRemotePort )
{
    FreeRTOS_Socket_t * xRetSocket = ensure_FreeRTOS_Socket_t_is_allocated();

    if( xRetSocket )
    {
        /* This test case is for IPv4. */
        __CPROVER_assume( xRetSocket->bits.bIsIPv6 == pdFALSE || xRetSocket->bits.bIsIPv6 == pdTRUE );
    }

    return xRetSocket;
}

/* Abstraction of pxGetNetworkBufferWithDescriptor */
NetworkBufferDescriptor_t * pxGetNetworkBufferWithDescriptor( size_t xRequestedSizeBytes,
                                                              TickType_t xBlockTimeTicks )
{
    NetworkBufferDescriptor_t * pxNetworkBuffer = safeMalloc( sizeof( NetworkBufferDescriptor_t ) );

    if( pxNetworkBuffer )
    {
        pxNetworkBuffer->pucEthernetBuffer = safeMalloc( xRequestedSizeBytes );
        __CPROVER_assume( pxNetworkBuffer->xDataLength == ipSIZE_OF_ETH_HEADER + sizeof( int32_t ) );
    }

    return pxNetworkBuffer;
}

/* Abstraction of uxIPHeaderSizePacket. Because we're testing IPv4 in this test case, the network buffer is
 * guaranteed to be IPv4 packet. Thus returns IPv4 header size here directly. */
size_t uxIPHeaderSizePacket( const NetworkBufferDescriptor_t * pxNetworkBuffer )
{
    size_t ret = ipSIZE_OF_IPv4_HEADER;

    if( lIsIPv6Packet )
    {
        ret = ipSIZE_OF_IPv6_HEADER;
    }

    return ret;
}

/* Abstraction of uxIPHeaderSizePacket. Because we're testing IPv4 in this test case, all socket handlers returned
 * by functions are for IPv4. Thus returns IPv4 header size here directly. */
size_t uxIPHeaderSizeSocket( const FreeRTOS_Socket_t * pxSocket )
{
    size_t ret = ipSIZE_OF_IPv4_HEADER;

    if( lIsIPv6Packet )
    {
        ret = ipSIZE_OF_IPv6_HEADER;
    }

    return ret;
}

void harness()
{
    NetworkBufferDescriptor_t * pxNetworkBuffer = safeMalloc( sizeof( NetworkBufferDescriptor_t ) );
    size_t uxBufferSize;
    EthernetHeader_t * pxEthernetHeader;

    lIsIPv6Packet = nondet_bool();

    /* To avoid asserting on the network buffer being NULL. */
    __CPROVER_assume( pxNetworkBuffer != NULL );
    if( lIsIPv6Packet )
    {
        __CPROVER_assume( uxBufferSize >= sizeof( TCPPacket_IPv6_t ) && uxBufferSize <= ipconfigNETWORK_MTU );
    }
    else
    {
        __CPROVER_assume( uxBufferSize >= sizeof( TCPPacket_t ) && uxBufferSize <= ipconfigNETWORK_MTU );
    }

    pxNetworkBuffer->pucEthernetBuffer = safeMalloc( uxBufferSize );

    /* To avoid asserting on the ethernet buffer being NULL. */
    __CPROVER_assume( pxNetworkBuffer->pucEthernetBuffer != NULL );

    if( lIsIPv6Packet )
    {
        /* Ethernet frame type is checked before calling xProcessReceivedTCPPacket_IPV6. */
        pxEthernetHeader = ( EthernetHeader_t * ) pxNetworkBuffer->pucEthernetBuffer;
        __CPROVER_assume( pxEthernetHeader->usFrameType == ipIPv6_FRAME_TYPE );
    }


    xProcessReceivedTCPPacket( pxNetworkBuffer );
}
