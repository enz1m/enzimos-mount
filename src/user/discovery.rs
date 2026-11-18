//! On-demand discovery of file servers on the local network.
//!
//! Nothing browses in the background. `Discover()` asks Avahi (mDNS/DNS-SD)
//! for SMB, SFTP, WebDAV, NFS and FTP services and sends one WS-Discovery
//! probe for Windows computers, naming them with a NetBIOS status query.
//! The whole search is bounded to a few seconds.

use crate::api::DiscoveredServer;
use futures_util::StreamExt;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use zbus::OwnedObjectPath;

/// Total time spent collecting answers.
pub const WINDOW: Duration = Duration::from_millis(2500);

const SERVICES: [(&str, &str); 7] = [
    ("_smb._tcp", "smb"),
    ("_sftp-ssh._tcp", "sftp"),
    ("_webdav._tcp", "dav"),
    ("_webdavs._tcp", "davs"),
    ("_nfs._tcp", "nfs"),
    ("_ftp._tcp", "ftp"),
    ("_device-info._tcp", ""),
];

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "smb" => 445,
        "sftp" => 22,
        "dav" => 80,
        "davs" => 443,
        "nfs" => 2049,
        "ftp" => 21,
        _ => 0,
    }
}

fn txt_path(txt: &[Vec<u8>]) -> String {
    txt.iter()
        .filter_map(|entry| {
            std::str::from_utf8(entry)
                .ok()?
                .strip_prefix("path=")
                .map(str::to_owned)
        })
        .next()
        .unwrap_or_default()
}

/// Build a connectable address for a resolved service.
#[must_use]
pub fn service_uri(scheme: &str, address: &str, port: u16, path: &str) -> Option<String> {
    let host: IpAddr = address.parse().ok()?;
    let host = match host {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(_) => return None,
    };
    let port = if port == default_port(scheme) || port == 0 {
        String::new()
    } else {
        format!(":{port}")
    };
    let path = path.trim_start_matches('/');
    let candidate = format!("{scheme}://{host}{port}/{path}");
    crate::uri::NetUri::parse(&candidate)
        .ok()
        .map(|u| u.display())
}

type Resolved = (
    i32,
    i32,
    String,
    String,
    String,
    String,
    i32,
    String,
    u16,
    Vec<Vec<u8>>,
    u32,
);

async fn avahi(connection: &zbus::Connection) -> Vec<DiscoveredServer> {
    let Ok(server) = zbus::Proxy::new(
        connection,
        "org.freedesktop.Avahi",
        "/",
        "org.freedesktop.Avahi.Server",
    )
    .await
    else {
        return Vec::new();
    };
    // Avahi 0.8+ offers race-free browsers (prepare, subscribe, then start)
    // on the Server2 interface.
    let Ok(server2) = zbus::Proxy::new(
        connection,
        "org.freedesktop.Avahi",
        "/",
        "org.freedesktop.Avahi.Server2",
    )
    .await
    else {
        return Vec::new();
    };
    let deadline = tokio::time::Instant::now() + WINDOW;
    let mut found = Vec::new();
    let mut browsers = Vec::new();
    for (service, scheme) in SERVICES {
        if scheme.is_empty() {
            continue;
        }
        let Ok(Ok(path)) = tokio::time::timeout(
            Duration::from_secs(1),
            server2.call::<_, _, OwnedObjectPath>(
                "ServiceBrowserPrepare",
                &(-1i32, 0i32, service, "local", 0u32),
            ),
        )
        .await
        else {
            continue;
        };
        let Ok(rule) = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.freedesktop.Avahi.ServiceBrowser")
            .member("ItemNew")
            .path(path.clone())
            .build()
        else {
            continue;
        };
        let Ok(stream) =
            zbus::MessageStream::for_match_rule(rule, connection, std::num::NonZeroUsize::new(64))
                .await
        else {
            continue;
        };
        let Ok(browser) = zbus::Proxy::new(
            connection,
            "org.freedesktop.Avahi",
            path.clone(),
            "org.freedesktop.Avahi.ServiceBrowser",
        )
        .await
        else {
            continue;
        };
        let _ = browser.call::<_, _, ()>("Start", &()).await;
        browsers.push((browser, stream, scheme));
    }
    let mut items: Vec<(String, String, String, &str)> = Vec::new();
    for (_, stream, scheme) in &mut browsers {
        while let Ok(Some(Ok(message))) = tokio::time::timeout_at(
            deadline.min(tokio::time::Instant::now() + Duration::from_millis(900)),
            stream.next(),
        )
        .await
        {
            if let Ok((_iface, _proto, name, kind, domain, _flags)) =
                message
                    .body()
                    .deserialize::<(i32, i32, String, String, String, u32)>()
            {
                items.push((name, kind, domain, scheme));
            }
        }
    }
    for (browser, _, _) in &browsers {
        let _ = browser.call::<_, _, ()>("Free", &()).await;
    }
    for (name, kind, domain, scheme) in items {
        let body = (
            -1i32,
            0i32,
            name.as_str(),
            kind.as_str(),
            domain.as_str(),
            0i32,
            0u32,
        );
        let resolve = server.call::<_, _, Resolved>("ResolveService", &body);
        if let Ok(Ok(resolved)) = tokio::time::timeout(Duration::from_millis(800), resolve).await {
            let (_, _, name, _, _, _host, _, address, port, txt, _) = resolved;
            if let Some(uri) = service_uri(scheme, &address, port, &txt_path(&txt)) {
                found.push(DiscoveredServer {
                    name,
                    uri,
                    source: "mdns".to_owned(),
                });
            }
        }
    }
    found
}

/// A NetBIOS node status request for `*`.
#[must_use]
pub fn nbstat_request(id: u16) -> Vec<u8> {
    let mut packet = id.to_be_bytes().to_vec();
    packet.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20]);
    packet.extend_from_slice(b"CK");
    packet.extend(std::iter::repeat_n(b'A', 30));
    packet.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    packet
}

/// The computer's unique file-server name from a node status response.
#[must_use]
pub fn nbstat_name(response: &[u8]) -> Option<String> {
    let count = usize::from(*response.get(56)?);
    (0..count)
        .filter_map(|i| response.get(57 + i * 18..57 + (i + 1) * 18))
        .find(|entry| matches!(entry[15], 0x20 | 0x00) && entry[16] & 0x80 == 0)
        .map(|entry| String::from_utf8_lossy(&entry[..15]).trim().to_owned())
        .filter(|name| !name.is_empty() && crate::uri::valid_host(name))
}

fn xaddr_host(text: &str) -> Option<Ipv4Addr> {
    let start = text.find("XAddrs>")? + "XAddrs>".len();
    let rest = text.get(start..)?;
    let urls = rest.get(..rest.find('<')?)?;
    urls.split_whitespace().find_map(|url| {
        let host = url.strip_prefix("http://")?.split(['/', ':']).next()?;
        host.parse().ok()
    })
}

async fn wsd() -> Vec<DiscoveredServer> {
    let Ok(socket) = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return Vec::new();
    };
    let _ = socket.set_multicast_ttl_v4(1);
    let probe = format!(
        concat!(
            r#"<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" "#,
            r#"xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" "#,
            r#"xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"#,
            r#"<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:{}</wsa:MessageID>"#,
            r#"</soap:Header><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>"#
        ),
        crate::secret::random_hex(16)
    );
    if socket
        .send_to(probe.as_bytes(), (Ipv4Addr::new(239, 255, 255, 250), 3702))
        .await
        .is_err()
    {
        return Vec::new();
    }
    let deadline = tokio::time::Instant::now() + WINDOW;
    let mut hosts = BTreeMap::new();
    let mut buffer = vec![0u8; 16 * 1024];
    while let Ok(Ok((n, from))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        let text = String::from_utf8_lossy(&buffer[..n]);
        if !text.contains("Computer") {
            continue;
        }
        let host = xaddr_host(&text).or_else(|| match from.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        });
        if let Some(host) = host {
            hosts.insert(host, ());
            if hosts.len() >= 64 {
                break;
            }
        }
    }
    let mut out = Vec::new();
    for host in hosts.into_keys() {
        let name = netbios_name(host).await.unwrap_or_else(|| host.to_string());
        out.push(DiscoveredServer {
            name,
            uri: format!("smb://{host}/"),
            source: "wsd".to_owned(),
        });
    }
    out
}

async fn netbios_name(host: Ipv4Addr) -> Option<String> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .ok()?;
    socket
        .send_to(&nbstat_request(0x4e5a), SocketAddr::from((host, 137)))
        .await
        .ok()?;
    let mut buffer = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_millis(400), socket.recv_from(&mut buffer))
        .await
        .ok()?
        .ok()?;
    nbstat_name(&buffer[..n])
}

/// Search the local network; bounded to about [`WINDOW`] plus name lookups.
pub async fn discover(system: Option<&zbus::Connection>) -> Vec<DiscoveredServer> {
    let mdns = async {
        match system {
            Some(connection) => avahi(connection).await,
            None => Vec::new(),
        }
    };
    let (mut found, windows) = tokio::join!(mdns, wsd());
    for server in windows {
        let host = crate::uri::NetUri::parse(&server.uri)
            .map(|u| u.host)
            .unwrap_or_default();
        let duplicate = found.iter().any(|f| {
            f.uri.starts_with("smb://")
                && crate::uri::NetUri::parse(&f.uri).is_ok_and(|u| u.host == host)
        });
        if !duplicate {
            found.push(server);
        }
    }
    found.sort_by(|a, b| (&a.name, &a.uri).cmp(&(&b.name, &b.uri)));
    found.dedup_by(|a, b| a.uri == b.uri);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_answers_become_safe_addresses() {
        assert_eq!(
            service_uri("smb", "192.168.1.5", 445, "").as_deref(),
            Some("smb://192.168.1.5/"),
            "default port omitted"
        );
        assert_eq!(
            service_uri("dav", "10.0.0.2", 8080, "/remote.php/dav").as_deref(),
            Some("dav://10.0.0.2:8080/remote.php/dav"),
            "txt path"
        );
        assert_eq!(
            service_uri("sftp", "fe80::1", 22, ""),
            None,
            "link-local IPv6 without scope is skipped"
        );
        assert_eq!(
            service_uri("smb", "-oProxy", 445, ""),
            None,
            "non-address refused"
        );

        let request = nbstat_request(7);
        assert_eq!(request.len(), 50, "header, encoded name, type and class");
        let mut response = vec![0u8; 57];
        response[56] = 2;
        let mut group = *b"WORKGROUP      \x00\x80\x00";
        group[16] = 0x80;
        response.extend_from_slice(&group);
        response.extend_from_slice(b"NAS-BOX        \x20\x04\x00");
        assert_eq!(
            nbstat_name(&response).as_deref(),
            Some("NAS-BOX"),
            "unique file-server name, group skipped"
        );
        assert_eq!(
            xaddr_host("<wsd:XAddrs>http://192.168.1.9:5357/abc</wsd:XAddrs>"),
            Some(Ipv4Addr::new(192, 168, 1, 9)),
            "XAddrs host"
        );
    }
}
