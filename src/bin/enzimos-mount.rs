//! Command-line client of `org.enzimos.Mount1`.
#![allow(
    clippy::print_stdout,
    reason = "a command-line tool reports on standard output"
)]

use enzimos_mount::api::{self, Snapshot};
use futures_util::StreamExt;
use std::collections::HashMap;
use zbus::{Fd, Variant};

const USAGE: &str = "usage: enzimos-mount COMMAND
  list [--json]                 drives, phones and network locations
  watch                         print each change
  mount ID                      mount an item
  login ID [--user U] [--domain D] [--remember]
                                mount with a password read from standard input
  unlock ID                     unlock an encrypted drive (passphrase on standard input)
  unmount ID [--force]          unmount
  eject ID | remove ID          eject, or unmount and power off the drive
  connect URI [--name N] [--save] [--auto] [--smb-version V] [--mount]
                                add a network location (prints its ID)
  update ID [--name N] [--save|--no-save] [--auto|--no-auto] [--user U] [--smb-version V] [--forget-password]
  startup ID on|off [--password-stdin]
                                mount a SMB/NFS location at startup, before login
  forget ID                     remove a location and its saved password
  trust ID FINGERPRINT...       trust an SFTP server key
  discover                      find servers on the local network
  shares URI [--user U] [--domain D] [--password-stdin]
  image PATH                    mount a disk image read-only
  cloud google_drive|onedrive|dropbox|nextcloud [SERVER]
                                add a cloud drive (sign in in the browser; prints its ID)
  format ID --type exfat|vfat|ntfs|ext4 [--label L] [--whole-drive]
                                quick-format a removable drive (prints the volume ID)";

fn fail(message: &str) -> ! {
    eprintln!("enzimos-mount: {message}");
    std::process::exit(1);
}

struct Args {
    positional: Vec<String>,
    flags: HashMap<String, Option<String>>,
}

fn parse(args: &[String]) -> Args {
    const VALUED: [&str; 6] = [
        "--name",
        "--user",
        "--domain",
        "--smb-version",
        "--type",
        "--label",
    ];
    let mut positional = Vec::new();
    let mut flags = HashMap::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if VALUED.contains(&arg.as_str()) {
            let value = iter
                .next()
                .unwrap_or_else(|| fail(&format!("{arg} needs a value")));
            flags.insert(arg.clone(), Some(value.clone()));
        } else if arg.starts_with("--") {
            flags.insert(arg.clone(), None);
        } else {
            positional.push(arg.clone());
        }
    }
    Args { positional, flags }
}

fn secret_from_stdin() -> std::os::fd::OwnedFd {
    let secret = enzimos_mount::secret::from_reader(std::io::stdin())
        .unwrap_or_else(|e| fail(&e.to_string()));
    enzimos_mount::secret::to_memfd(&secret).unwrap_or_else(|e| fail(&e.to_string()))
}

fn empty_secret() -> std::os::fd::OwnedFd {
    enzimos_mount::secret::to_memfd(&enzimos_mount::secret::Secret::default())
        .unwrap_or_else(|e| fail(&e.to_string()))
}

fn print_snapshot(snapshot: &Snapshot) {
    for item in &snapshot.items {
        let state = match &item.state {
            api::State::Failed { reason } => format!("failed: {reason}"),
            other => serde_json::to_value(other)
                .ok()
                .and_then(|v| v["state"].as_str().map(str::to_owned))
                .unwrap_or_default(),
        };
        let path = item
            .mount_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        println!(
            "{:<28} {:<8} {:<12} {:<28} {}",
            item.id,
            format!("{:?}", item.kind).to_lowercase(),
            state,
            item.label,
            path
        );
    }
}

fn options(args: &Args) -> HashMap<&'static str, Variant<'static>> {
    let mut options = HashMap::new();
    if args.flags.contains_key("--forget-password") {
        options.insert("forget_password", Variant::from(true));
    }
    if args.flags.contains_key("--save") {
        options.insert("save", Variant::from(true));
    }
    if args.flags.contains_key("--no-save") {
        options.insert("save", Variant::from(false));
    }
    if args.flags.contains_key("--auto") {
        options.insert("auto_connect", Variant::from(true));
    }
    if args.flags.contains_key("--no-auto") {
        options.insert("auto_connect", Variant::from(false));
    }
    for (flag, key) in [
        ("--name", "label"),
        ("--user", "username"),
        ("--smb-version", "smb_version"),
    ] {
        if let Some(Some(value)) = args.flags.get(flag) {
            options.insert(key, Variant::from(value.clone()));
        }
    }
    options
}

async fn run(proxy: &zbus::Proxy<'_>, command: &str, args: &Args) -> zbus::Result<()> {
    let id = || {
        args.positional
            .first()
            .cloned()
            .unwrap_or_else(|| fail("missing ID"))
    };
    match command {
        "list" => {
            let json: String = proxy.call("List", &()).await?;
            if args.flags.contains_key("--json") {
                println!("{json}");
            } else {
                print_snapshot(&serde_json::from_str(&json).unwrap_or_default());
            }
        }
        "watch" => {
            let mut stream = proxy.receive_signal("Changed").await?;
            while let Some(message) = stream.next().await {
                if let Ok(json) = message.body().deserialize::<String>() {
                    println!("{json}");
                }
            }
        }
        "mount" => println!("{}", proxy.call::<_, _, String>("Mount", &(id(),)).await?),
        "login" => {
            let user = args
                .flags
                .get("--user")
                .cloned()
                .flatten()
                .unwrap_or_default();
            let domain = args
                .flags
                .get("--domain")
                .cloned()
                .flatten()
                .unwrap_or_default();
            let fd = secret_from_stdin();
            let path: String = proxy
                .call(
                    "MountWithCredentials",
                    &(
                        id(),
                        user,
                        domain,
                        Fd::from(&fd),
                        args.flags.contains_key("--remember"),
                    ),
                )
                .await?;
            println!("{path}");
        }
        "unlock" => {
            let fd = secret_from_stdin();
            println!(
                "{}",
                proxy
                    .call::<_, _, String>("Unlock", &(id(), Fd::from(&fd)))
                    .await?
            );
        }
        "unmount" => {
            proxy
                .call::<_, _, ()>("Unmount", &(id(), args.flags.contains_key("--force")))
                .await?
        }
        "eject" => proxy.call::<_, _, ()>("Eject", &(id(),)).await?,
        "remove" => proxy.call::<_, _, ()>("SafelyRemove", &(id(),)).await?,
        "connect" => {
            let name = args
                .flags
                .get("--name")
                .cloned()
                .flatten()
                .unwrap_or_default();
            let mut opts = options(args);
            opts.remove("label");
            let new_id: String = proxy.call("AddLocation", &(id(), name, opts)).await?;
            println!("{new_id}");
            if args.flags.contains_key("--mount") {
                println!("{}", proxy.call::<_, _, String>("Mount", &(new_id,)).await?);
            }
        }
        "update" => {
            proxy
                .call::<_, _, ()>("UpdateLocation", &(id(), options(args)))
                .await?
        }
        "forget" => proxy.call::<_, _, ()>("RemoveLocation", &(id(),)).await?,
        "startup" => {
            let enabled = match args.positional.get(1).map(String::as_str) {
                Some("on") => true,
                Some("off") => false,
                _ => fail("startup needs on or off"),
            };
            let fd = if args.flags.contains_key("--password-stdin") {
                secret_from_stdin()
            } else {
                empty_secret()
            };
            proxy
                .call::<_, _, ()>("SetMountAtBoot", &(id(), enabled, Fd::from(&fd)))
                .await?;
        }
        "trust" => {
            let fingerprints: Vec<String> = args.positional.iter().skip(1).cloned().collect();
            proxy
                .call::<_, _, ()>("TrustHostKey", &(id(), fingerprints))
                .await?;
        }
        "discover" => println!("{}", proxy.call::<_, _, String>("Discover", &()).await?),
        "shares" => {
            let user = args
                .flags
                .get("--user")
                .cloned()
                .flatten()
                .unwrap_or_default();
            let domain = args
                .flags
                .get("--domain")
                .cloned()
                .flatten()
                .unwrap_or_default();
            let fd = if args.flags.contains_key("--password-stdin") {
                secret_from_stdin()
            } else {
                empty_secret()
            };
            println!(
                "{}",
                proxy
                    .call::<_, _, String>("ListShares", &(id(), user, domain, Fd::from(&fd)))
                    .await?
            );
        }
        "image" => println!(
            "{}",
            proxy.call::<_, _, String>("MountImage", &(id(),)).await?
        ),
        "cloud" => {
            let server = args.positional.get(1).cloned().unwrap_or_default();
            println!(
                "{}",
                proxy
                    .call::<_, _, String>("AddCloud", &(id(), server))
                    .await?
            );
        }
        "format" => {
            let mut opts: HashMap<&str, Variant<'_>> = HashMap::new();
            for (flag, key) in [("--type", "type"), ("--label", "label")] {
                if let Some(Some(value)) = args.flags.get(flag) {
                    opts.insert(key, Variant::from(value.clone()));
                }
            }
            opts.insert(
                "whole_drive",
                Variant::from(args.flags.contains_key("--whole-drive")),
            );
            println!(
                "{}",
                proxy.call::<_, _, String>("Format", &(id(), opts)).await?
            );
        }
        _ => fail(USAGE),
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let all: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = all.first().cloned() else {
        fail(USAGE)
    };
    if command == "--help" || command == "-h" {
        println!("{USAGE}");
        return;
    }
    let args = parse(&all[1..]);
    let connection = zbus::Connection::session()
        .await
        .unwrap_or_else(|e| fail(&format!("no session bus: {e}")));
    let proxy = zbus::Proxy::new(&connection, api::BUS_NAME, api::OBJECT_PATH, api::INTERFACE)
        .await
        .unwrap_or_else(|e| fail(&e.to_string()));
    if let Err(error) = run(&proxy, &command, &args).await {
        match &error {
            zbus::Error::MethodError(name, message, _) => {
                let kind = name.as_str().rsplit('.').next().unwrap_or_default();
                eprintln!(
                    "enzimos-mount: {kind}: {}",
                    message.as_deref().unwrap_or_default()
                );
                std::process::exit(match kind {
                    "NeedsCredentials" => 3,
                    "HostKeyUnknown" | "HostKeyChanged" => 4,
                    "Busy" => 5,
                    _ => 1,
                });
            }
            other => fail(&other.to_string()),
        }
    }
}
