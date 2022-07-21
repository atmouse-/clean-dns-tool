use futures::stream::StreamExt;
use getopts::Options;
use redbpf::{load::Loader, xdp, HashMap};
use std::env;
use std::net::Ipv4Addr;
use std::process;
use std::ptr;
use tokio;
use tokio::runtime;
use tokio::signal;


use clean_dns_bpf::clean_dns::Query;
use clean_dns_bpf::clean_dns::Connection;

fn main() {
    if unsafe { libc::geteuid() } != 0 {
        println!("bpf-clean-dns: You must be root to use eBPF!");
        process::exit(-1);
    }

    let opts = match parse_opts() {
        Some(o) => o,
        None => process::exit(1),
    };

    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let _ = rt.block_on(async {
        let mut loader = Loader::load(probe_code()).expect("error loading probe");

        // attach the xdp program
        for prog in loader.xdps_mut() {
            prog.attach_xdp(&opts.interface, xdp::Flags::default())
                .expect("error attaching XDP program")
        }

        tokio::spawn(async move {
            // process perf events sent by the XDP program
            while let Some((name, events)) = loader.events.next().await {
                for event in events {
                    match name.as_str() {
                        //"query" => {
                        //    let query = unsafe { ptr::read(event.as_ptr() as *const Query) };
                        //    println!("{}", query.count_block);
                        //}
                        "connections" => {
                            let conn = unsafe { ptr::read(event.as_ptr() as *const Connection) };
                            println!(
                                "{} dns from {:?}",
                                if conn.allowed == 1 {
                                    "Allowed"
                                } else {
                                    "Drop"
                                },
                                Ipv4Addr::from(conn.source_ip)
                            );
                        }
                        _ => panic!("unexpected event"),
                    }
                }
            }
        });

        signal::ctrl_c().await
    });

}


struct Opts {
    interface: String,
}

fn parse_opts() -> Option<Opts> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.reqopt(
        "i",
        "interface",
        "the network interface to listen on",
        "INTERFACE",
    );
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("{}\n", f);
            print_usage(&program, opts);
            return None;
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return None;
    }
    let interface = matches.opt_str("i");
    if interface.is_none() {
        print_usage(&program, opts);
        return None;
    };

    Some(Opts {
        interface: interface.unwrap(),
    })
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/clean-dns/clean-dns.elf"
    ))
}
