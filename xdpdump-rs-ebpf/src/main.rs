#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use core::{mem, ptr};

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(16_777_216u32, 0);

#[xdp]
pub fn xdpdump_rs(ctx: XdpContext) -> u32 {
    match try_xdpdump_rs(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

fn try_xdpdump_rs(ctx: XdpContext) -> Result<u32, ()> {
    // Search for IPv4 packets only
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // Search for UDP only
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    let src_port = unsafe { u16::from_be((*udphdr).source) };

    if src_port != 53 {
        return Ok(xdp_action::XDP_PASS);
    }

    debug!(&ctx, "Dropping packet from source {:i}", source);

    const U16_SIZE: usize = mem::size_of::<u16>();
    const SIZE: usize = U16_SIZE + 1500;

    match RING_BUF.reserve::<[u8; SIZE]>(0) {
        Some(mut event) => {
            let len = ctx.data_end() - ctx.data();

            // We check if packet len is greater than our reserved buffer size
            if aya_ebpf::check_bounds_signed(len as i64, 1, 1500) == false {
                event.discard(0);
                return Ok(xdp_action::XDP_DROP);
            }

            unsafe {
                // we first save into the buffer the packet length.
                // Useful on userspace to retrieve the correct amount of bytes and not some bytes not part of the packet.
                ptr::write_unaligned(event.as_mut_ptr() as *mut _, len as u16);

                // We copy the entire content of the packet to the buffer (L2 to L7)
                match aya_ebpf::helpers::gen::bpf_xdp_load_bytes(
                    ctx.ctx,
                    0,
                    event.as_mut_ptr().byte_add(U16_SIZE) as *mut _,
                    len as u32,
                ) {
                    0 => event.submit(0),
                    _ => event.discard(0),
                }
            }
        }
        None => {
            info!(&ctx, "Cannot reserve space in ring buffer.");
        }
    };

    Ok(xdp_action::XDP_DROP)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
