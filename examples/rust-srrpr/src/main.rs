use std::sync::Mutex;
use log::{info};
use clap::Parser;

static EXIT_FLAG: Mutex<i32> = Mutex::new(0);

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
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

    // server_unix init
    let server_unix = cio::CioListener::unix_bind("/tmp/srrp")
        .expect("listen unix socket failed");

    // server_tcp init
    let server_tcp = cio::CioListener::tcp_bind("127.0.0.1:3824")
        .expect("listen tcp socket failed");

    // srrp init
    let mut router = srrp::SrrpRouter::new().unwrap();
    router.add_listener(server_unix, 0xf1);
    router.add_listener(server_tcp, 0xf2);

    // signal
    ctrlc::set_handler(move || {
        *EXIT_FLAG.lock().unwrap() = 1;
    }).expect("Error setting Ctrl-C handler");

    // main loop
    loop {
        if *EXIT_FLAG.lock().unwrap() == 1 {
            break;
        }

        if router.wait() == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }

        while let Some(pac) = router.iter() {
            if pac.dstid == 0xf1 || pac.dstid == 0xf2 {
                info!("srrp_packet: srcid:{}, dstid:{}, {}?{}",
                       pac.srcid, pac.dstid, pac.anchor, pac.payload);
                let resp = srrp::Srrp::new_response(
                    pac.dstid, pac.srcid, &pac.anchor,
                    "j:{\"err\":404,\"msg\":\"Service not found\"}")
                    .unwrap();
                info!("resp: srcid:{}, dstid:{}, {}?{}",
                       resp.srcid, resp.dstid, resp.anchor, resp.payload);
                router.send(&resp);
            } else {
                info!("srrp_packet: {}?{}", pac.anchor, pac.payload);
                router.forward(&pac);
            }
        }
    }
}
