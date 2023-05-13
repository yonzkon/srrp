use std::sync::Mutex;
use log::{debug};
use clap::Parser;

static EXIT_FLAG: Mutex<i32> = Mutex::new(0);

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
    #[clap(short, long, default_value = "unix://tmp/srrp")]
    unix_addr: String,
    #[clap(short, long, default_value = "tcp://127.0.0.1:3824")]
    tcp_addr: String,
}

fn main() {
    // parse args
    let args = Args::parse();
    match args.debug {
        0 => {
            std::env::set_var("RUST_LOG", "info");
            srrp::log_set_level(srrp::LogLevel::Info);
            println!("Debug mode is off");
        }
        1 => {
            std::env::set_var("RUST_LOG", "debug");
            srrp::log_set_level(srrp::LogLevel::Debug);
            println!("Debug mode is on");
        }
        2 => {
            std::env::set_var("RUST_LOG", "trace");
            srrp::log_set_level(srrp::LogLevel::Trace);
            println!("Trace mode is on");
        }
        _ => println!("Don't be crazy"),
    }

    // logger init
    simple_logger::SimpleLogger::new().env().init().unwrap();

    // unix_server init
    let unix_server = cio::CioListener::bind(&args.unix_addr)
        .expect("listen unix socket failed");

    // tcp_server init
    let tcp_server = cio::CioListener::bind(&args.tcp_addr)
        .expect("listen tcp socket failed");

    // srrp init
    let mut router = srrp::SrrpRouter::new().unwrap();
    router.add_listener(unix_server, "router-unix");
    router.add_listener(tcp_server, "router-tcp");

    // signal
    ctrlc::set_handler(move || {
        *EXIT_FLAG.lock().unwrap() = 1;
    }).expect("Error setting Ctrl-C handler");

    // main loop
    loop {
        if *EXIT_FLAG.lock().unwrap() == 1 {
            break;
        }

        if router.wait(10 * 1000) == 0 {
            continue;
        }

        while let Some(pac) = router.iter() {
            if pac.dstid != "router-unix" && pac.dstid != "router-tcp" {
                debug!("forward srrp:{}", std::str::from_utf8(&pac.raw).unwrap());
                router.forward(&pac);
            }
        }
    }
}
