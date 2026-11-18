//! One-shot root worker for `enzimos-mount-system`: one kernel mount or unmount.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !rustix::process::geteuid().is_root() {
        eprintln!("enzimos-mount-worker is started by enzimos-mount-system only");
        std::process::exit(2);
    }
    std::process::exit(enzimos_mount::system::worker::main(&args));
}
