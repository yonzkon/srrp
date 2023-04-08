use std::sync::Mutex;
use log::{info, debug};
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

    // unix_server init
    let unix_server = cio::CioListener::bind("unix://tmp/srrp")
        .expect("listen unix socket failed");

    // tcp_server init
    let tcp_server = cio::CioListener::bind("tcp://127.0.0.1:3824")
        .expect("listen tcp socket failed");

    // srrp init
    let mut router = srrp::SrrpRouter::new().unwrap();
    router.add_listener(unix_server, 0xf1);
    router.add_listener(tcp_server, 0xf2);

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
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }

        while let Some(pac) = router.iter() {
            if pac.dstid == 0xf1 || pac.dstid == 0xf2 {
                debug!("serv srrp:{}", std::str::from_utf8(&pac.raw).unwrap());
                let resp = srrp::Srrp::new_response(
                    pac.dstid, pac.srcid, &pac.anchor,
                    "j:{\"err\":404,\"msg\":\"Service not found\"}")
                    .unwrap();
                info!("resp: srcid:{}, dstid:{}, {}?{}",
                       resp.srcid, resp.dstid, resp.anchor, resp.payload);
                router.send(&resp);
            } else {
                debug!("forward srrp:{}", std::str::from_utf8(&pac.raw).unwrap());
                router.forward(&pac);
            }
        }
    }
}
