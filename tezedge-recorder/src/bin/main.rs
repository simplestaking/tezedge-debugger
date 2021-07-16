// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

#[cfg(all(not(target_env = "msvc"), feature = "jemallocator"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() -> anyhow::Result<()> {
    use std::{
        env,
        process::Command,
        time::Duration,
        thread,
        sync::{
            Arc,
            atomic::{Ordering, AtomicBool},
        },
        io::ErrorKind,
    };
    use tezedge_recorder::{System, database::rocks::Db, main_loop};

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        ctrlc::set_handler(move || running.store(false, Ordering::Relaxed))?;
    }

    let mut system = System::<Db>::load_config()?;
    system.run_dbs(running.clone());

    if system.need_bpf() {
        let bpf = if env::args().find(|a| a == "--run-bpf").is_some() {
            let h = Command::new("bpf-recorder").spawn()
                .or_else(|e| {
                    if e.kind() == ErrorKind::NotFound {
                        Command::new("./target/none/release/bpf-recorder").spawn()
                    } else {
                        Err(e)
                    }
                });
            match h {
                Ok(h) => {
                    thread::sleep(Duration::from_millis(500));
                    if let Err(error) = main_loop::run(&mut system, running) {
                        log::error!("cannot intercept p2p messages: {}", error)
                    }
                    Some(h)
                },
                Err(error) => {
                    log::error!("cannot run bpf: {:?}", error);
                    None
                },
            }
        } else {
            None
        };

        let _ = bpf;
    }
    system.join();

    Ok(())
}
