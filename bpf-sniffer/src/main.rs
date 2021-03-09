use std::{fs, io::{BufReader, BufRead}, os::unix::{fs::PermissionsExt, io::AsRawFd, net::UnixListener}, process, str::FromStr};
use bpf_sniffer_lib::{BpfModule, Command, SocketId};
use tracing::Level;
use structopt::StructOpt;
use passfd::FdPassingExt;

#[derive(StructOpt)]
pub struct Opts {
    #[structopt(
        short,
        long,
        default_value = "/tmp/bpf-sniffer.sock",
        help = "communication channel with the sniffer",
    )]
    socket: String,
}

fn main() {
    let Opts { socket  } = StructOpt::from_args();

    sudo::escalate_if_needed().expect("failed to obtain superuser permission");
    ctrlc::set_handler(move || process::exit(0))
        .expect("failed to setup ctrl+c handler");

    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let module = BpfModule::load();
    tracing::info!("load bpf module");

    let rb = module.main_buffer_map();

    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("failed to bind socket");

    let mut perms = fs::metadata(&socket)
        .expect("failed to get permission of socket")
        .permissions();
    perms.set_mode(0o666);
    fs::set_permissions(&socket, perms)
        .expect("failed to set permission for socket");
    tracing::info!("set permission for: {}", &socket);

    let (stream, _) = listener.accept().expect("failed to accept connection");
    stream.send_fd(rb.as_raw_fd()).expect("failed to send ring buffer access");

    let stream = BufReader::new(stream);
    for line in stream.lines() {
        match line {
            Ok(line) => {
                match Command::from_str(&line) {
                    Ok(Command::WatchPort { port }) => {
                        module.watch_port(port);
                        tracing::info!("watching port: {}", port);
                    },
                    Ok(Command::IgnoreConnection { pid, fd }) => {
                        module.ignore(SocketId { pid, fd });
                        tracing::info!("ignore connection pid: {}, fd: {}", pid, fd);
                    },
                    Err(error) => {
                        tracing::warn!("bad command: {}", error);
                    },
                }
            },
            Err(error) => tracing::warn!("failed to read command: {}", error),
        }
    }
}