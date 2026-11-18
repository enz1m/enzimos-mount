//! Root service `org.enzimos.MountSystem1`; D-Bus activated, exits when idle.
//!
//! `--boot` mounts the stored startup shares in the background and exits when
//! all are mounted (enzimos-mount-boot.service); `--unmount-all` detaches every
//! kernel network mount before the network stops (enzimos-mount-cleanup.service).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match args.as_slice() {
        [] => "serve",
        [flag] if flag == "--boot" => "boot",
        [flag] if flag == "--unmount-all" => "unmount-all",
        _ => {
            eprintln!("enzimos-mount-system takes no arguments except --boot or --unmount-all");
            std::process::exit(2);
        }
    };
    if mode == "serve" {
        // Replies go to session services, which translate them for their user.
        enzimos_mount::i18n::defer();
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("<3>runtime: {error}");
            std::process::exit(1);
        }
    };
    match mode {
        "boot" => runtime.block_on(enzimos_mount::system::boot::run()),
        "unmount-all" => runtime.block_on(enzimos_mount::system::boot::unmount_all()),
        _ => {
            if let Err(error) = runtime.block_on(enzimos_mount::system::serve()) {
                eprintln!("<3>enzimos-mount-system: {error}");
                std::process::exit(1);
            }
        }
    }
}
