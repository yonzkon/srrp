use log::{info, debug, warn};
use clap::Parser;
use std::net::TcpListener;
use std::thread::spawn;
use tungstenite::accept;
use tungstenite::protocol::Message;

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

    let server = TcpListener::bind("0.0.0.0:3825").unwrap();
    for stream in server.incoming() {
        spawn (move || {
            let mut ws = accept(stream.unwrap()).unwrap();
            ws.get_mut().set_nonblocking(true)
                .expect("set_nonblocking call failed");

            let mut nodeid = rand::random::<u32>();
            while nodeid <= 0xff {
                nodeid = rand::random::<u32>();
            }

            let client = cio::CioStream::connect("unix://tmp/srrp")
                .expect("connect unix socket failed");
            let conn = srrp::SrrpConnect::new(client, &nodeid.to_string()).unwrap();

            loop {
                // read message from websocket, then send packet to srrp network
                match ws.read_message() {
                    Ok(msg) => {
                        if msg.is_text() {
                            debug!("{}", msg.to_text().unwrap());
                            if let Ok(jdata) = json::parse(&msg.into_text().unwrap().to_string()) {
                                if jdata["leader"].as_str() != None &&
                                    jdata["leader"].as_str().unwrap().chars().next() != None &&
                                    jdata["dstid"].as_str() != None &&
                                    jdata["anchor"].as_str() != None &&
                                    jdata["payload"].as_str() != None {
                                    if let Some(pac) = srrp::Srrp::new(
                                        jdata["leader"].as_str().unwrap().chars().next().unwrap(),
                                        1, &nodeid.to_string(),
                                        jdata["dstid"].as_str().unwrap(),
                                        jdata["anchor"].as_str().unwrap(),
                                        jdata["payload"].as_str().unwrap()) {
                                        conn.send(&pac);
                                    } else {
                                        match ws.write_message(Message::Text(
                                            "Format Error".to_string())) {
                                            Ok(_) => (),
                                            Err(e) => { warn!("write message:{}", e); }
                                        };
                                    }
                                }
                            }
                        } else if msg.is_close() {
                            break;
                        }
                    },
                    Err(_) => ()
                }

                // wait for srrp packet, idle in 10ms
                if conn.wait(10 * 1000) == 0 {
                    continue;
                }

                // read packet from srrp network, then send message to websocket
                while let Some(pac) = conn.iter() {
                    debug!("recv srrp:{}", std::str::from_utf8(&pac.raw).unwrap());
                    let mut payload = json::JsonValue::from("");
                    if &pac.payload[0..2] == "j:" {
                        match json::parse(&pac.payload[2..]) {
                            Ok(j) => { payload = j; },
                            Err(e) => { warn!("parse payload:{}", e); },
                        }
                    } else if &pac.payload[0..2] == "t:" {
                        payload = json::JsonValue::from(&pac.payload[2..]);
                    }
                    let tmp = json::object!{
                        leader: pac.leader,
                        srcid: pac.srcid[0..],
                        dstid: pac.dstid[0..],
                        anchor: pac.anchor[0..],
                        payload: payload,
                    };
                    match ws.write_message(Message::Text(tmp.dump())) {
                        Ok(_) => (),
                        Err(e) => { warn!("write message:{}", e); }
                    }
                    //match ws.write_message(Message::Text(
                    //    std::str::from_utf8(&pac.raw).unwrap().to_string())) {
                    //    Ok(_) => (),
                    //    Err(e) => { warn!("write message:{}", e); }
                    //}
                }
            }

            info!("websocket fin, exit ...");
        });
    }
}
