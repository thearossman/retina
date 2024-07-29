use crate::dpdk;
use crate::filter::hardware::{flow_item::*, flow_attr::*, flow_action::*};
use crate::port::PortId;
use crate::protocols::packet::{tcp::TCP_PROTOCOL, udp::UDP_PROTOCOL};
use crate::FiveTuple;
use std::mem;
use std::net::SocketAddr;
use std::ffi::c_void;

use super::HIGH_PRIORITY;

// Notes:
// - Other rules use RSS redirection - would that be faster? 
// - This iterates through ports - should probably pass the portId that the
//   packet was received on through the processing pipeline
// - PASSTHRU would override DROP
// - Nothing creative with batching/buffering or special core to do this

fn populate_ipv4(ipv4_mask: &mut dpdk::rte_flow_item_ipv4, 
                 ipv4_spec: &mut dpdk::rte_flow_item_ipv4, 
                 five_tuple: &FiveTuple) -> Option<dpdk::rte_flow_item>
{
    if let SocketAddr::V4(orig) = five_tuple.orig {
        if let SocketAddr::V4(resp) = five_tuple.resp {
            ipv4_spec.hdr.src_addr = orig.ip().to_bits();
            ipv4_spec.hdr.dst_addr = resp.ip().to_bits();
            ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
            ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
            
            let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
            p_item.type_ = dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV4;
            p_item.spec = &ipv4_spec as *const _ as *const c_void;
            p_item.mask = &ipv4_mask as *const _ as *const c_void;
            return Some(p_item);
        }
    }
    None
}

fn populate_ipv6(ipv6_mask: &mut dpdk::rte_flow_item_ipv6, 
                 ipv6_spec: &mut dpdk::rte_flow_item_ipv6, 
                 five_tuple: &FiveTuple) -> Option<dpdk::rte_flow_item>
{
    if let SocketAddr::V6(orig) = five_tuple.orig {
        if let SocketAddr::V6(resp) = five_tuple.resp {
            // Addr is already NBO; preserve endianness 
            ipv6_spec.hdr.src_addr = orig.ip().to_bits().to_ne_bytes();
            ipv6_spec.hdr.dst_addr = resp.ip().to_bits().to_ne_bytes();
            ipv6_mask.hdr.src_addr = [0xFF; 16];
            ipv6_mask.hdr.dst_addr = [0xFF; 16];

            let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
            p_item.type_ = dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV6;
            p_item.spec = &ipv6_spec as *const _ as *const c_void;
            p_item.mask = &ipv6_mask as *const _ as *const c_void;
            return Some(p_item);
        }
    }
    None
}

fn get_ports(five_tuple: &FiveTuple) -> (u16, u16)
{
    let src_port = match five_tuple.orig {
        SocketAddr::V4(v4) => {
            v4.port()
        },
        SocketAddr::V6(v6) => {
            v6.port()
        }
    };

    let dst_port = match five_tuple.resp {
        SocketAddr::V4(v4) => {
            v4.port()
        },
        SocketAddr::V6(v6) => {
            v6.port()
        }
    };

    (src_port, dst_port)
}

fn populate_udp(udp_mask: &mut dpdk::rte_flow_item_udp, 
                udp_spec: &mut dpdk::rte_flow_item_udp, 
                five_tuple: &FiveTuple) -> dpdk::rte_flow_item
{
    let (src_port, dst_port) = get_ports(five_tuple);
    udp_spec.hdr.dst_port = dst_port;
    udp_mask.hdr.dst_port = 0xFFFF;
    udp_spec.hdr.src_port = src_port;
    udp_mask.hdr.src_port = 0xFFFF;

    let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
    p_item.type_ = dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_UDP;
    p_item.spec = &udp_spec as *const _ as *const c_void;
    p_item.mask = &udp_mask as *const _ as *const c_void;
    p_item
}

fn populate_tcp(tcp_mask: &mut dpdk::rte_flow_item_tcp, 
                tcp_spec: &mut dpdk::rte_flow_item_tcp,
                five_tuple: &FiveTuple) -> dpdk::rte_flow_item
{
    let (src_port, dst_port) = get_ports(five_tuple);
    tcp_spec.hdr.dst_port = dst_port;
    tcp_mask.hdr.dst_port = 0xFFFF;
    tcp_spec.hdr.src_port = src_port;
    tcp_mask.hdr.src_port = 0xFFFF;

    let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
    p_item.type_ = dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_TCP;
    p_item.spec = &tcp_spec as *const _ as *const c_void;
    p_item.mask = &tcp_mask as *const _ as *const c_void;
    p_item
}

pub fn block_flow(port_ids: &Vec<PortId>, five_tuple: &FiveTuple) {
    let mut ipv4_spec: dpdk::rte_flow_item_ipv4;
    let mut ipv4_mask: dpdk::rte_flow_item_ipv4;
    let mut udp_spec: dpdk::rte_flow_item_udp;  
    let mut udp_mask: dpdk::rte_flow_item_udp;  
    let mut tcp_spec: dpdk::rte_flow_item_tcp;  
    let mut tcp_mask: dpdk::rte_flow_item_tcp;  
    let mut ipv6_spec: dpdk::rte_flow_item_ipv6;
    let mut ipv6_mask: dpdk::rte_flow_item_ipv6;

    let attr = FlowAttribute::new(0, HIGH_PRIORITY);
    let mut pattern_rules: PatternRules  = vec![];

    // Start with ETH
    append_eth(&mut pattern_rules);

    // Build pattern for five-tuple (IP -> L4 protocol)
    match five_tuple.orig {
        SocketAddr::V4(_) => {
            ipv4_spec = unsafe { mem::zeroed() };
            ipv4_mask = unsafe { mem::zeroed() };
            if let Some(p_item) = populate_ipv4(&mut ipv4_mask, 
                                                               &mut ipv4_spec, 
                                                               five_tuple) {
                pattern_rules.push(p_item);
            } else {
                return;
            }
            
            match five_tuple.proto {
                UDP_PROTOCOL => {
                    udp_spec = unsafe {mem::zeroed() };
                    udp_mask =  unsafe {mem::zeroed() };
                    pattern_rules.push(populate_udp(&mut udp_mask, 
                                                    &mut udp_spec, 
                                                    five_tuple));
                },
                TCP_PROTOCOL => {
                    tcp_spec = unsafe {mem::zeroed() };
                    tcp_mask =  unsafe {mem::zeroed() };
                    pattern_rules.push(populate_tcp(&mut tcp_mask, 
                                                    &mut tcp_spec, 
                                                    five_tuple));
                },
                _ => { }
            }
        }, 
        SocketAddr::V6(_) => {
            ipv6_spec = unsafe {mem::zeroed() };
            ipv6_mask =  unsafe {mem::zeroed() };
            if let Some(p_item) = populate_ipv6(&mut ipv6_mask,
                                                               &mut ipv6_spec, 
                                                               five_tuple) {
                pattern_rules.push(p_item);
            } else {
                return;
            }
            match five_tuple.proto {
                UDP_PROTOCOL => {
                    udp_spec = unsafe {mem::zeroed() };
                    udp_mask =  unsafe {mem::zeroed() };
                    pattern_rules.push(populate_udp(&mut udp_mask, 
                                                    &mut udp_spec, 
                                                    five_tuple));
                },
                TCP_PROTOCOL => {
                    tcp_spec = unsafe {mem::zeroed() };
                    tcp_mask =  unsafe {mem::zeroed() };
                    pattern_rules.push(populate_tcp(&mut tcp_mask, 
                                                    &mut tcp_spec, 
                                                    five_tuple));
                },
                _ => { }
            }
        }
    }

    // End flow pattern
    append_end(&mut pattern_rules);

    // Check if rule is supported; if so, install
    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    for port_id in port_ids {
        // \note Other rules use RSS (see `create_rule`) redirection
        // as a faster (?) alternative to `drop`
        let mut action = FlowAction::new(*port_id);
        action.append_drop();
        action.finish();
        let res = unsafe { dpdk::rte_flow_validate(port_id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,) };
        if res == 0 {
            let _ = unsafe { dpdk::rte_flow_create(
                    port_id.raw(), 
                    attr.raw() as *const _,
                    pattern_rules.as_ptr(),
                    action.rules.as_ptr(),
            &mut error as *mut _,
            ) };
        }
    }
    
}