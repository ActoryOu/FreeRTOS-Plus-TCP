/*
 * FreeRTOS+TCP <DEVELOPMENT BRANCH>
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/**
 * @file FreeRTOS_ICMP.c
 * @brief Implements the Internet Control Message Protocol for the FreeRTOS+TCP network stack.
 */

/* Standard includes. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_IP_Timers.h"
#include "FreeRTOS_IP_Utils.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_ARP.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DHCP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"
#include "FreeRTOS_DNS.h"

/*
 * Utility functions for the light weight IP timers.
 */
static void prvIPTimerStart( IPTimer_t * pxTimer,
                             TickType_t xTime );
static BaseType_t prvIPTimerCheck( IPTimer_t * pxTimer );
static void prvIPTimerReload( IPTimer_t * pxTimer,
                              TickType_t xTime );

/*
 * A timer for each of the following processes, all of which need attention on a
 * regular basis
 */

/** @brief Timer to limit the maximum time a packet should be stored while
 *         awaiting an ARP resolution. */
static IPTimer_t xARPResolutionTimer;

/** @brief ARP timer, to check its table entries. */
static IPTimer_t xARPTimer;
#if ( ipconfigUSE_TCP != 0 )
    /** @brief TCP timer, to check for timeouts, resends. */
    static IPTimer_t xTCPTimer;
#endif
#if ( ipconfigDNS_USE_CALLBACKS != 0 )
    /** @brief DNS timer, to check for timeouts when looking-up a domain. */
    static IPTimer_t xDNSTimer;
#endif

/** @brief 'xAllNetworksUp' becomes pdTRUE as soon as all network interfaces have
 * been initialised. */
static BaseType_t xAllNetworksUp = pdFALSE;

/** @brief As long as not all networks are up, repeat initialisation by calling the
 * xNetworkInterfaceInitialise() function of the interfaces that are not ready. */
static IPTimer_t xNetworkTimer;

/**
 * @brief Calculate the maximum sleep time remaining. It will go through all
 *        timers to see which timer will expire first. That will be the amount
 *        of time to block in the next call to xQueueReceive().
 *
 * @return The maximum sleep time or ipconfigMAX_IP_TASK_SLEEP_TIME,
 *         whichever is smaller.
 */
TickType_t xCalculateSleepTime( void )
{
    TickType_t uxMaximumSleepTime;

    /* Start with the maximum sleep time, then check this against the remaining
     * time in any other timers that are active. */
    uxMaximumSleepTime = ipconfigMAX_IP_TASK_SLEEP_TIME;

    if( xARPTimer.bActive != pdFALSE_UNSIGNED )
    {
        if( xARPTimer.ulRemainingTime < uxMaximumSleepTime )
        {
            uxMaximumSleepTime = xARPTimer.ulRemainingTime;
        }
    }

    #if ( ipconfigUSE_DHCP == 1 ) || ( ipconfigUSE_RA == 1 )
        {
            NetworkEndPoint_t * pxEndPoint = FreeRTOS_FirstEndPoint( NULL );

            while( pxEndPoint != NULL )
            {
                if( pxEndPoint->xDHCP_RATimer.bActive != pdFALSE_UNSIGNED )
                {
                    if( pxEndPoint->xDHCP_RATimer.ulRemainingTime < xMaximumSleepTime )
                    {
                        xMaximumSleepTime = pxEndPoint->xDHCP_RATimer.ulRemainingTime;
                    }
                }

                pxEndPoint = FreeRTOS_NextEndPoint( NULL, pxEndPoint );
            }
        }
    #endif /* ( ipconfigUSE_DHCP == 1 ) || ( ipconfigUSE_RA == 1 ) */

    #if ( ipconfigUSE_TCP == 1 )
        {
            if( xTCPTimer.bActive != pdFALSE_UNSIGNED )
            {
                if( xTCPTimer.ulRemainingTime < uxMaximumSleepTime )
                {
                    uxMaximumSleepTime = xTCPTimer.ulRemainingTime;
                }
            }
        }
    #endif

    #if ( ipconfigDNS_USE_CALLBACKS != 0 )
        {
            if( xDNSTimer.bActive != pdFALSE_UNSIGNED )
            {
                if( xDNSTimer.ulRemainingTime < uxMaximumSleepTime )
                {
                    uxMaximumSleepTime = xDNSTimer.ulRemainingTime;
                }
            }
        }
    #endif

    return uxMaximumSleepTime;
}
/*-----------------------------------------------------------*/

/**
 * @brief Check the network timers (ARP/DHCP/DNS/TCP) and if they are
 *        expired, send an event to the IP-Task.
 */
void vCheckNetworkTimers( void )
{
    NetworkInterface_t * pxInterface;

    /* Is it time for ARP processing? */
    if( prvIPTimerCheck( &xARPTimer ) != pdFALSE )
    {
        ( void ) xSendEventToIPTask( eARPTimerEvent );
    }

    /* Is the ARP resolution timer expired? */
    if( prvIPTimerCheck( &xARPResolutionTimer ) != pdFALSE )
    {
        if( pxARPWaitingNetworkBuffer != NULL )
        {
            /* Disable the ARP resolution timer. */
            vIPSetARPResolutionTimerEnableState( pdFALSE );

            /* We have waited long enough for the ARP response. Now, free the network
             * buffer. */
            vReleaseNetworkBufferAndDescriptor( pxARPWaitingNetworkBuffer );

            /* Clear the pointer. */
            pxARPWaitingNetworkBuffer = NULL;

            iptraceDELAYED_ARP_TIMER_EXPIRED();
        }
    }

    #if ( ipconfigUSE_DHCP == 1 ) || ( ipconfigUSE_RA == 1 )
        {
            /* Is it time for DHCP processing? */
            NetworkEndPoint_t * pxEndPoint = FreeRTOS_FirstEndPoint( NULL );

            while( pxEndPoint != NULL )
            {
                if( prvIPTimerCheck( &( pxEndPoint->xDHCP_RATimer ) ) != pdFALSE )
                {
                    #if ( ipconfigUSE_DHCP == 1 )
                        if( END_POINT_USES_DHCP( pxEndPoint ) )
                        {
                            ( void ) xSendDHCPEvent( pxEndPoint );
                        }
                    #endif /* ( ipconfigUSE_DHCP == 1 ) */

                    #if ( ipconfigUSE_RA != 0 )
                        if( END_POINT_USES_RA( pxEndPoint ) )
                        {
                            vRAProcess( pdFALSE, pxEndPoint );
                        }
                    #endif /* ( ipconfigUSE_RA != 0 ) */
                }

                pxEndPoint = FreeRTOS_NextEndPoint( NULL, pxEndPoint );
            }
        }
    #endif /* ( ipconfigUSE_DHCP == 1 ) || ( ipconfigUSE_RA == 1 ) */

    #if ( ipconfigDNS_USE_CALLBACKS != 0 )
        {
            /* Is it time for DNS processing? */
            if( prvIPTimerCheck( &xDNSTimer ) != pdFALSE )
            {
                vDNSCheckCallBack( NULL );
            }
        }
    #endif /* ipconfigDNS_USE_CALLBACKS */

    #if ( ipconfigUSE_TCP == 1 )
        {
            BaseType_t xWillSleep;
            TickType_t xNextTime;
            BaseType_t xCheckTCPSockets;

            /* If the IP task has messages waiting to be processed then
             * it will not sleep in any case. */
            if( uxQueueMessagesWaiting( xNetworkEventQueue ) == 0U )
            {
                xWillSleep = pdTRUE;
            }
            else
            {
                xWillSleep = pdFALSE;
            }

            /* Sockets need to be checked if the TCP timer has expired. */
            xCheckTCPSockets = prvIPTimerCheck( &xTCPTimer );

            /* Sockets will also be checked if there are TCP messages but the
            * message queue is empty (indicated by xWillSleep being true). */
            if( ( xProcessedTCPMessage != pdFALSE ) && ( xWillSleep != pdFALSE ) )
            {
                xCheckTCPSockets = pdTRUE;
            }

            if( xCheckTCPSockets != pdFALSE )
            {
                /* Attend to the sockets, returning the period after which the
                 * check must be repeated. */
                xNextTime = xTCPTimerCheck( xWillSleep );
                prvIPTimerStart( &xTCPTimer, xNextTime );
                xProcessedTCPMessage = 0;
            }
        }

        /* See if any socket was planned to be closed. */
        vSocketCloseNextTime( NULL );
    #endif /* ipconfigUSE_TCP == 1 */

    /* Is it time to trigger the repeated NetworkDown events? */
    if( xAllNetworksUp == pdFALSE )
    {
        if( prvIPTimerCheck( &( xNetworkTimer ) ) != pdFALSE )
        {
            BaseType_t xUp = pdTRUE;

            for( pxInterface = pxNetworkInterfaces; pxInterface != NULL; pxInterface = pxInterface->pxNext )
            {
                if( pxInterface->bits.bInterfaceUp == pdFALSE_UNSIGNED )
                {
                    xUp = pdFALSE;
                    FreeRTOS_NetworkDown( pxInterface );
                }
            }

            xAllNetworksUp = xUp;
        }
    }
}
/*-----------------------------------------------------------*/

/**
 * @brief Start an IP timer. The IP-task has its own implementation of a timer
 *        called 'IPTimer_t', which is based on the FreeRTOS 'TimeOut_t'.
 *
 * @param[in] pxTimer: Pointer to the IP timer. When zero, the timer is marked
 *                     as expired.
 * @param[in] xTime: Time to be loaded into the IP timer.
 */
static void prvIPTimerStart( IPTimer_t * pxTimer,
                             TickType_t xTime )
{
    vTaskSetTimeOutState( &pxTimer->xTimeOut );
    pxTimer->ulRemainingTime = xTime;

    if( xTime == ( TickType_t ) 0 )
    {
        pxTimer->bExpired = pdTRUE_UNSIGNED;
    }
    else
    {
        pxTimer->bExpired = pdFALSE_UNSIGNED;
    }

    pxTimer->bActive = pdTRUE_UNSIGNED;
}
/*-----------------------------------------------------------*/

void vIPTimerStartARPResolution( TickType_t xTime )
{
    prvIPTimerStart( &( xARPResolutionTimer ), xTime );
}
/*-----------------------------------------------------------*/

/**
 * @brief Sets the reload time of an IP timer and restarts it.
 *
 * @param[in] pxTimer: Pointer to the IP timer.
 * @param[in] xTime: Time to be reloaded into the IP timer.
 */
static void prvIPTimerReload( IPTimer_t * pxTimer,
                              TickType_t xTime )
{
    pxTimer->ulReloadTime = xTime;
    prvIPTimerStart( pxTimer, xTime );
}
/*-----------------------------------------------------------*/

#if ( ipconfigUSE_TCP == 1 )
    void vTCPTimerReload( TickType_t xTime )
    {
        prvIPTimerReload( &xTCPTimer, xTime );
    }
#endif
/*-----------------------------------------------------------*/

void vARPTimerReload( TickType_t xTime )
{
    prvIPTimerReload( &xARPTimer, xTime );
}
/*-----------------------------------------------------------*/

#if ( ipconfigUSE_DHCP == 1 )

/**
 * @brief Reload the DHCP timer.
 *
 * @param[in] ulLeaseTime: The reload value.
 */
    void vDHCPTimerReload( TickType_t xLeaseTime )
    {
        prvIPTimerReload( &xDHCPTimer, xLeaseTime );
    }
#endif /* ipconfigUSE_DHCP */
/*-----------------------------------------------------------*/

#if ( ipconfigDNS_USE_CALLBACKS != 0 )

/**
 * @brief Reload the DNS timer.
 *
 * @param[in] ulCheckTime: The reload value.
 */
    void vDNSTimerReload( uint32_t ulCheckTime )
    {
        prvIPTimerReload( &xDNSTimer, ulCheckTime );
    }
#endif /* ipconfigDNS_USE_CALLBACKS != 0 */
/*-----------------------------------------------------------*/

void vNetworkTimerReload( TickType_t xTime )
{
    prvIPTimerReload( &xNetworkTimer, xTime );
}
/*-----------------------------------------------------------*/

/**
 * @brief Check the IP timer to see whether an IP event should be processed or not.
 *
 * @param[in] pxTimer: Pointer to the IP timer.
 *
 * @return If the timer is expired then pdTRUE is returned. Else pdFALSE.
 */
static BaseType_t prvIPTimerCheck( IPTimer_t * pxTimer )
{
    BaseType_t xReturn;

    if( pxTimer->bActive == pdFALSE_UNSIGNED )
    {
        /* The timer is not enabled. */
        xReturn = pdFALSE;
    }
    else
    {
        /* The timer might have set the bExpired flag already, if not, check the
         * value of xTimeOut against ulRemainingTime. */
        if( pxTimer->bExpired == pdFALSE_UNSIGNED )
        {
            if( xTaskCheckForTimeOut( &( pxTimer->xTimeOut ), &( pxTimer->ulRemainingTime ) ) != pdFALSE )
            {
                pxTimer->bExpired = pdTRUE_UNSIGNED;
            }
        }

        if( pxTimer->bExpired != pdFALSE_UNSIGNED )
        {
            prvIPTimerStart( pxTimer, pxTimer->ulReloadTime );
            xReturn = pdTRUE;
        }
        else
        {
            xReturn = pdFALSE;
        }
    }

    return xReturn;
}
/*-----------------------------------------------------------*/

#if ( ipconfigUSE_TCP == 1 )

/**
 * @brief Enable/disable the TCP timer.
 *
 * @param[in] xExpiredState: pdTRUE - set as expired; pdFALSE - set as non-expired.
 */
    void vIPSetTCPTimerExpiredState( BaseType_t xExpiredState )
    {
        xTCPTimer.bActive = pdTRUE_UNSIGNED;

        if( xExpiredState != pdFALSE )
        {
            xTCPTimer.bExpired = pdTRUE_UNSIGNED;
        }
        else
        {
            xTCPTimer.bExpired = pdFALSE_UNSIGNED;
        }
    }
/*-----------------------------------------------------------*/
#endif /* if ( ipconfigUSE_TCP == 1 ) */

/**
 * @brief Enable/disable the ARP timer.
 *
 * @param[in] xEnableState: pdTRUE - enable timer; pdFALSE - disable timer.
 */
void vIPSetARPTimerEnableState( BaseType_t xEnableState )
{
    if( xEnableState != pdFALSE )
    {
        xARPTimer.bActive = pdTRUE_UNSIGNED;
    }
    else
    {
        xARPTimer.bActive = pdFALSE_UNSIGNED;
    }
}
/*-----------------------------------------------------------*/

/**
 * @brief Enable or disable the ARP resolution timer.
 *
 * @param[in] xEnableState: pdTRUE if the timer must be enabled, pdFALSE otherwise.
 */
void vIPSetARPResolutionTimerEnableState( BaseType_t xEnableState )
{
    if( xEnableState != pdFALSE )
    {
        xARPResolutionTimer.bActive = pdTRUE_UNSIGNED;
    }
    else
    {
        xARPResolutionTimer.bActive = pdFALSE_UNSIGNED;
    }
}
/*-----------------------------------------------------------*/

#if ( ipconfigUSE_DHCP == 1 ) || ( ipconfigUSE_RA == 1 ) || ( ipconfigUSE_DHCPv6 == 1 )

/**
 * @brief Enable or disable the DHCP/DHCPv6/RA timer.
 *
 * @param[in] pxEndPoint: The end-point that needs to acquire an IP-address.
 * @param[in] xEnableState: pdTRUE - enable timer; pdFALSE - disable timer.
 */
    void vIPSetDHCP_RATimerEnableState( struct xNetworkEndPoint * pxEndPoint,
                                        BaseType_t xEnableState )
    {
        FreeRTOS_printf( ( "vIPSetDHCP_RATimerEnableState: %s\n", ( xEnableState != 0 ) ? "On" : "Off" ) );

        /* 'xDHCP_RATimer' is shared between DHCP (IPv4) and RA/SLAAC (IPv6). */
        if( xEnableState != pdFALSE )
        {
            pxEndPoint->xDHCP_RATimer.bActive = pdTRUE_UNSIGNED;
        }
        else
        {
            pxEndPoint->xDHCP_RATimer.bActive = pdFALSE_UNSIGNED;
        }
    }
#endif /* ( ipconfigUSE_DHCP == 1 ) || ( ipconfigUSE_RA == 1 ) || ( ipconfigUSE_DHCPv6 == 1 ) */
/*-----------------------------------------------------------*/

#if ( ipconfigUSE_DHCP == 1 ) || ( ipconfigUSE_RA == 1 )

/**
 * @brief Set the reload time of the DHCP/DHCPv6/RA timer.
 *
 * @param[in] pxEndPoint: The end-point that needs to acquire an IP-address.
 * @param[in] uxClockTicks: The number of clock-ticks after which the timer should expire.
 */
    void vIPReloadDHCP_RATimer( struct xNetworkEndPoint * pxEndPoint,
                                TickType_t uxClockTicks )
    {
        FreeRTOS_printf( ( "vIPReloadDHCP_RATimer: %lu\n", uxClockTicks ) );
        prvIPTimerReload( &( pxEndPoint->xDHCP_RATimer ), uxClockTicks );
    }
#endif /* ( ipconfigUSE_DHCP == 1 ) || ( ipconfigUSE_RA == 1 ) */
/*-----------------------------------------------------------*/

#if ( ipconfigDNS_USE_CALLBACKS == 1 )

/**
 * @brief Enable/disable the DNS timer.
 *
 * @param[in] xEnableState: pdTRUE - enable timer; pdFALSE - disable timer.
 */
    void vIPSetDNSTimerEnableState( BaseType_t xEnableState )
    {
        if( xEnableState != 0 )
        {
            xDNSTimer.bActive = pdTRUE_UNSIGNED;
        }
        else
        {
            xDNSTimer.bActive = pdFALSE_UNSIGNED;
        }
    }

#endif /* ipconfigDNS_USE_CALLBACKS == 1 */
/*-----------------------------------------------------------*/
