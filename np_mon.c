/*
 * NP trafmon driver
 *
 * Copyright (c) 2009 Bonelli Nicola <bonelli@antifork.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. 2.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/errno.h>        /* error codes */
#include <linux/etherdevice.h>  /* eth_type_trans */

#include <linux/inet.h>
#include <linux/if_ether.h>

#include <net/dst.h>
#include <net/arp.h>
#include <net/mac80211.h>

#include "np_packet.h"
#include "np_mon_ioctl.h"

MODULE_DESCRIPTION("Network Processor Monitor Interface");
MODULE_AUTHOR("Francesco Oppedisano <f.oppedisano@netresult.it> - Nicola Bonelli <bonelli@antifork.org>");
MODULE_LICENSE("Dual BSD/GPL");

/* typedefs */

int np_mon_pkt_recv(struct sk_buff *skb, struct net_device *dev, struct packet_type *ptype, struct net_device *orig_dev);

int nmon = 1;                       /* number of mon interfaces */
struct net_device **np_mon_devs;    /* array of ptr to monitor interface */

unsigned int np_clock = 27;         /* nanoseconds: NP 1/frequency */

ktime_t utc0;                       /* utc of the first batch frame */
unsigned long long tick0 = 0;       /* tick of the first packet within the first batch frame */

struct packet_type np_packet_type = 
{
    .type = __constant_htons(NP_PKT_TYPE),
    .func = np_mon_pkt_recv,
};

/* struct np_mon_priv: statistics and stuff */

struct np_mon_priv {

    struct net_device_stats stats;  /* stats of device */ 
    
    // struct sk_buff_head rx_queue;   /* queue of incoming packets ?! to be initialized to skb_queue_head_init */
    // struct sk_buff *skb;            /* useful ? */ 
    // spinlock_t lock;                /* to protect this structure */
    // int rx_int_enabled;
    // int status;
};

/* module parameters */

module_param(nmon, int, 0);
MODULE_PARM_DESC(nmon, "Number of mon interfaces");

module_param(np_clock, int, 0);
MODULE_PARM_DESC(np_clock, "NP clock (nsec)");

/* 
 * np_packet: packet handler 
 */

int np_mon_pkt_recv(struct sk_buff * skb, struct net_device * dev, struct packet_type * pkt_type, struct net_device * device2)
{
    struct net_device *mon;
    char * p, *p_end; // cursor 

    struct sk_buff * nskb;  

    if (!skb)
        return 0;
 
    p = (char *)skb->data;
 
    /* update utc0 at the arrival of the first packet */

    if (!utc0.tv64) { 
        utc0 = ktime_get_real();
    }
  
    for ( ; p < (char *)skb_tail_pointer(skb); p = p_end ) {

        unsigned long long tick;

        struct np_mon_priv * priv=netdev_priv(dev);
        struct np_packet_hdr * np_h; 
        struct ethhdr * eh;

        unsigned short flow_id;
        unsigned short frag_len;
        unsigned short mac_len;

        if ( (p + sizeof(struct np_packet_hdr)) >= (char *) skb_tail_pointer(skb) ) {
            /* incomplete header */
            printk(KERN_WARNING "np_mon: incomplete np header\n");
            break;
        }
     
        /* read the np_packet header */
        np_h = (struct np_packet_hdr *)p;

        /* update utc0 and tick0 at the arrival of the first packet */

        if (!tick0) 
        {
            tick0 = (unsigned long long)ntohl(np_h->tstamp_hi)*1000000000 +
                    (unsigned long long)ntohl(np_h->tstamp_lo);
        }

        tick = (unsigned long long)ntohl(np_h->tstamp_hi)*1000000000 +
               (unsigned long long)ntohl(np_h->tstamp_lo);

        /* ----------------------------------------------------- */

        // printk(KERN_WARNING "np_mon: frag_len=%d\n", ntohs(np_h->frag_len));

        /* p and p_end delimit the np fragment */
        p += sizeof(struct np_packet_hdr);
        p_end = p + ntohs(np_h->frag_len);
        
        if (p_end > (char *) skb_tail_pointer(skb) ) {
            /* incomplete fragment */
            printk(KERN_WARNING "np_mon: incomplete fragment in np_packet\n");
            p_end = skb_tail_pointer(skb);
        } 

        frag_len = (p_end - p);
        flow_id = ntohs(np_h->flow_id);

        /* demultiplex sanity check */
        if ( flow_id >= nmon ) {
            printk(KERN_WARNING "np_mon: flow_id out of range\n");
            continue; 
        }

        mon  = np_mon_devs[flow_id];
        priv = netdev_priv(mon);

        mac_len = skb_network_header(skb)-skb_mac_header(skb);

#ifdef ZERO_COPY
        nskb = skb_clone(skb, GFP_KERNEL);
        if (unlikely(!nskb)) {
             if (printk_ratelimit())
 		        printk(KERN_WARNING "np_mon: %s memory squeeze, dropping packet.\n", mon->name);
 			priv->stats.rx_dropped++;
 			break;
        }

        nskb->data = p - mac_len;
        skb_reset_tail_pointer(nskb);

        skb_copy_to_linear_data(nskb, skb_mac_header(skb), mac_len);
        skb_put(nskb, frag_len + mac_len); 
#else
        /* create a new skb */

        nskb = dev_alloc_skb(frag_len + mac_len + 2);
        if (unlikely(!nskb)) {
             if (printk_ratelimit())
 		        printk(KERN_WARNING "np_mon: %s memory squeeze, dropping packet.\n", mon->name);
 			priv->stats.rx_dropped++;
 			break;
        }

        skb_reserve(nskb, 2);     

        skb_copy_to_linear_data_offset(nskb, 0, skb_mac_header(skb), mac_len);
        skb_copy_to_linear_data_offset(nskb, mac_len, p, frag_len);

        skb_put(nskb, frag_len + mac_len); 
#endif

        /* update the newly created sk_buff */
        nskb->dev = mon;
        nskb->ip_summed = CHECKSUM_UNNECESSARY;

        /* update the timestamp */
        nskb->tstamp = ktime_add_ns( utc0, (tick-tick0)* np_clock); 

        /* update the protocol */
        skb_reset_mac_header(nskb);
        
        eh = eth_hdr(nskb);
        eh->h_proto = htons(ETH_P_IP);
        // eh->h_proto = htons(frag_len); /* = ntohs(np_h->frag_len) unless the fragment is incomplete */

        nskb->protocol = eth_type_trans(nskb, mon);

        priv->stats.rx_packets++;
		priv->stats.rx_bytes += ntohs(np_h->pack_len);

        netif_receive_skb(nskb);
    }

    kfree_skb(skb);
    return 0;
}

////////////////////////////////////////////////////////////////////////////

/* open and release */

int mon_open(struct net_device *dev)
{
    printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);
    netif_start_queue(dev);
    return 0;
}

int mon_close(struct net_device *dev)
{
    printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);
    netif_stop_queue(dev);
    return 0;
}

/* ioctl commands */

int mon_ioctl (struct net_device* dev, struct ifreq* rq, int cmd)
{
    printk(KERN_DEBUG "np_mon: ioctl %d not supported!\n",cmd);
    return EOPNOTSUPP;
}


int mon_set_mac_address(struct net_device *dev, void *p)
{
    struct sockaddr * sa = p;

    // printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);
    if (!is_valid_ether_addr(sa->sa_data))
        return -EADDRNOTAVAIL;

    memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);
    return 0; /* success */
}


/* return statistics to the caller */

struct net_device_stats *mon_stats(struct net_device *dev)
{
    struct np_mon_priv *priv = netdev_priv(dev);
    // printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);
    return &priv->stats;
}

/* configuration changes (passed on by ifconfig) */

int mon_config(struct net_device *dev, struct ifmap *map)
{
    // printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);

    if (dev->flags & IFF_UP) /* can't act on a running interface */
        return -EBUSY;

    /* Don't allow changing the I/O address */
    if (map->base_addr != dev->base_addr) {
        printk(KERN_WARNING "np_mon: Can't change I/O address\n");
        return -EOPNOTSUPP;
    }

    /* Allow changing the IRQ */
    if (map->irq != dev->irq) {
        dev->irq = map->irq;
        printk(KERN_WARNING "np_mon: Changing irq makes no sense for me!\n");
        /* request_irq() is delayed to open-time */
    }

    /* ignore other fields */
    return 0;
}

void mon_rx(struct net_device *dev, struct sk_buff *pkt)
{
    struct np_mon_priv *priv = netdev_priv(dev);

    // printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);

    priv->stats.rx_packets++;
    priv->stats.rx_bytes += pkt->data_len;

    netif_receive_skb(pkt);
    return;
}


int mon_tx(struct sk_buff *skb, struct net_device *dev)
{
    struct np_mon_priv *priv = netdev_priv(dev);

    // printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);

    priv->stats.tx_packets++;
    priv->stats.tx_bytes += skb->len;
    
    dev_kfree_skb(skb);
    return 0; 
}

/////////////////////////////////////////////////////////////////////

int mon_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
    const struct ethhdr *eth = eth_hdr(skb);
    // printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);
    memcpy(haddr, eth->h_source, ETH_ALEN);
    return ETH_ALEN;
}

int mon_header(struct sk_buff *skb, struct net_device *dev,
               unsigned short type,
               const void *daddr, const void *saddr, unsigned len)
{
    struct ethhdr *eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);

    // printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);

    if (type != ETH_P_802_3)
        eth->h_proto = htons(type);
    else
        eth->h_proto = htons(len);

    /*
     *      Set the source hardware address.
     */

    if (!saddr)
        saddr = dev->dev_addr;
    memcpy(eth->h_source, saddr, ETH_ALEN);

    if (daddr) {
        memcpy(eth->h_dest, daddr, ETH_ALEN);
        return ETH_HLEN;
    }

    /*
     *      Anyway, the loopback-device should never use this function...
     */

    if (dev->flags & (IFF_LOOPBACK | IFF_NOARP)) {
        memset(eth->h_dest, 0, ETH_ALEN);
        return ETH_HLEN;
    }

    return -ETH_HLEN;
}

/**
 * eth_rebuild_header- rebuild the Ethernet MAC header.
 * @skb: socket buffer to update
 *
 * This is called after an ARP or IPV6 ndisc it's resolution on this
 * sk_buff. We now let protocol (ARP) fill in the other fields.
 *
 * This routine CANNOT use cached dst->neigh!
 * Really, it is used only when dst->neigh is wrong.
 */

int mon_rebuild_header(struct sk_buff *skb)
{
    struct ethhdr *eth = (struct ethhdr *)skb->data;
    struct net_device *dev = skb->dev;

    printk(KERN_INFO "np_mon: %s\n", __FUNCTION__);
    switch (eth->h_proto) {
        #ifdef CONFIG_INET
            case __constant_htons(ETH_P_IP):
                return arp_find(eth->h_dest, skb);
        #endif
    default:
        printk(KERN_DEBUG
               "%s: unable to resolve type %X addresses.\n",
               dev->name, (int)eth->h_proto);

        memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
        break;
    }

    return 0;
}

////////////////////////////////////////////////////////////////

const struct header_ops mon_header_ops ____cacheline_aligned = {
    .create         = mon_header,
    .parse          = mon_header_parse,
    .rebuild        = mon_rebuild_header,
    .cache          = NULL, // mon_header_cache,
    .cache_update   = NULL, // mon_header_cache_update,
};

void np_mon_setup(struct net_device *dev)
{
    struct np_mon_priv *priv;
    
    printk( KERN_DEBUG "np_mon_setup: net_device@%p\n", dev);
    ether_setup(dev); /* assign some of the fields */

    // set by ether_setup():
    //
    // dev->type            = ARPHRD_ETHER;
    // dev->hard_header_len = ETH_HLEN;
    // dev->mtu             = ETH_DATA_LEN;
    // dev->addr_len        = ETH_ALEN;

    dev->header_ops      = &mon_header_ops;

    dev->set_config      = mon_config;
    dev->hard_start_xmit = mon_tx;
    dev->do_ioctl        = mon_ioctl;
    dev->get_stats       = mon_stats;

    dev->change_mtu      = NULL; // mon_change_mtu;

    dev->set_mac_address = mon_set_mac_address;

    dev->open            = mon_open;
    dev->stop            = mon_close;

    dev->flags          |= IFF_NOARP;
    dev->features        = NETIF_F_NO_CSUM;
    dev->tx_queue_len    = 0; /* ethernet queue len */

    random_ether_addr(dev->dev_addr); 

    dev->tx_timeout      = NULL; // mon_tx_timeout;
    dev->watchdog_timeo  = 0;

    /*
     * Then, initialize the priv field. This encloses the statistics
     * and a few private fields.
     */

    priv = netdev_priv(dev);
    memset(priv, 0, sizeof(struct np_mon_priv));
 
    // skb_queue_head_init(&(priv->rx_queue));
    // spin_lock_init(&priv->lock);
    // mon_rx_ints(dev, 1);  /* enable receive interrupts */
}


int __init np_mon_init_one(int index) 
{
    struct net_device *dev;
    int err;

    dev = alloc_netdev(sizeof(struct np_mon_priv), "mon%d", np_mon_setup);
    if (dev == NULL)
        return -ENOMEM;

    err = register_netdev(dev);
    if (err) {
        free_netdev(dev);
        return err;
    }

    np_mon_devs[index] = dev; 
    return 0;
}


void __exit np_mon_free_one(int index)
{
    unregister_netdev( np_mon_devs[index] );
    free_netdev( np_mon_devs[index] );
}

/* init and exit module functions */

int __init np_mon_init_module(void)
{
    int i, err = 0;

    np_mon_devs = kmalloc(nmon * sizeof(struct net_device *), GFP_KERNEL);
    if (np_mon_devs == NULL)
        return -ENOMEM;

    for(i=0; i < nmon && !err; i++) {
        err = np_mon_init_one(i);
    }

    if (err)
        goto fail;

    printk(KERN_INFO "registering protocol: 0x%x.\n", NP_PKT_TYPE);
    dev_add_pack(&np_packet_type);

#ifdef ZERO_COPY
    printk(KERN_INFO "np_mon loaded [ZERO_COPY].\n" );
#else
    printk(KERN_INFO "np_mon loaded.\n" );
#endif

    return 0;

fail:
    i--;
    while (--i >=0)
        np_mon_free_one(i);     

    return err;
}

void __exit np_mon_exit_module(void)
{
    int i;

    dev_remove_pack(&np_packet_type);

    for(i=0; i< nmon; i++)
        np_mon_free_one(i);

    kfree(np_mon_devs);
    printk(KERN_INFO "np_mon released.\n");
}   

module_init(np_mon_init_module);
module_exit(np_mon_exit_module);

