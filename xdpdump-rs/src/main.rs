use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;

use std::time::{SystemTime, UNIX_EPOCH};
use std::{ptr, slice};

use pcap_file_tokio::pcap::{PcapPacket, PcapWriter};

use tokio::{
    fs::File,
    io::{unix::AsyncFd, AsyncWriteExt, BufWriter},
    sync::watch,
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    pcap_out: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdpdump-rs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdpdump-rs"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("xdpdump_rs").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let ring_dump = aya::maps::RingBuf::try_from(bpf.take_map("RING_BUF").unwrap()).unwrap();
    let file_out = File::create(opt.pcap_out.as_str())
        .await
        .expect("Error creating file out");

    // BufWriter to avoid a syscall per write. BufWriter will manage that for us and reduce the amound of syscalls.
    let stream = BufWriter::with_capacity(8192, file_out);
    let mut pcap_writer = PcapWriter::new(stream).await.expect("Error writing file");

    // Create a channel to signal task termination
    let (tx, rx) = watch::channel(false);

    let pcapdump_task = tokio::spawn(async move {
        let mut rx = rx.clone();
        let mut async_fd = AsyncFd::new(ring_dump).unwrap();

        loop {
            tokio::select! {
                _ = async_fd.readable_mut() => {
                    // wait till it is ready to read and read
                    let mut guard = async_fd.readable_mut().await.unwrap();
                    let rb = guard.get_inner_mut();

                    while let Some(read) = rb.next() {
                        let ptr = read.as_ptr();

                        // retrieve packet len first then packet data
                        let size = unsafe { ptr::read_unaligned::<u16>(ptr as *const u16) };
                        let data = unsafe { slice::from_raw_parts(ptr.byte_add(2), size.into()) };

                        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

                        let packet = PcapPacket::new(ts, size as u32, data);
                        pcap_writer.write_packet(&packet).await.unwrap();
                    }

                    guard.clear_ready();
                },
                _ = rx.changed() => {
                    if *rx.borrow() {
                        break;
                    }
                }
            }
        }

        // End of program, flush the buffer
        let mut buf_writer = pcap_writer.into_writer();
        buf_writer.flush().await.unwrap();
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    // Signal the task to stop
    tx.send(true).unwrap();

    // wait for the task to finish
    pcapdump_task.await.unwrap();

    info!("Exiting...");

    Ok(())
}
