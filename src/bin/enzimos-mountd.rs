//! Session service `org.enzimos.Mount1`: drives, phones and network locations.

fn main() {
    if std::env::args().len() > 1 {
        eprintln!("enzimos-mountd takes no arguments; it is started by the user session");
        std::process::exit(2);
    }
    // One event thread is plenty: every slow operation runs in a child process
    // or a bounded blocking task.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(32)
        .thread_keep_alive(std::time::Duration::from_secs(5))
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("<3>runtime: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = runtime.block_on(enzimos_mount::user::serve()) {
        eprintln!("<3>enzimos-mountd: {error}");
        std::process::exit(1);
    }
}
