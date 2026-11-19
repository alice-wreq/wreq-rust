use std::{net::SocketAddr, pin::Pin};

use btls::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{Ssl, SslAcceptor, SslMethod},
    x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use wreq::{
    Client,
    tls::{TlsInfo, trust::CertStore},
};

/// Self-signed certificate valid for `wreq.test` and `192.0.2.1`.
fn self_signed() -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "wreq test")
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("wreq.test")
        .ip("192.0.2.1")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();

    (builder.build(), key)
}

async fn serve(cert: &X509, key: &PKey<Private>) -> SocketAddr {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(cert).unwrap();
    acceptor.set_private_key(key).unwrap();
    let acceptor = acceptor.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut stream = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            tokio::spawn(async move {
                if Pin::new(&mut stream).accept().await.is_ok() {
                    let mut buf = [0; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn verify_host_overrides_uri_host() {
    let (cert, key) = self_signed();
    let der = cert.to_der().unwrap();
    let url = format!("https://{}/", serve(&cert, &key).await);

    let get = |host: &'static str| {
        let store = CertStore::builder()
            .add_der_cert(&der)
            .verify_host(host)
            .build()
            .unwrap();
        let client = Client::builder()
            .tls_cert_store(store)
            .tls_verify_hostname(false)
            .no_proxy()
            .build()
            .unwrap();
        client.get(&url).send()
    };

    // The URI names 127.0.0.1, which the certificate does not cover.
    assert!(get("wreq.test").await.unwrap().status().is_success());
    assert!(get("192.0.2.1").await.unwrap().status().is_success());
    assert!(get("other.test").await.is_err());
}

#[tokio::test]
async fn self_signed_peer_certificate_can_be_trusted_explicitly() {
    let (cert, key) = self_signed();
    let addr = serve(&cert, &key).await;
    let url = format!("https://wreq.test:{}/", addr.port());
    let builder = || Client::builder().no_proxy().resolve("wreq.test", addr);

    let response = builder()
        .tls_cert_verification(false)
        .tls_info(true)
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let peer = response
        .extensions()
        .get::<TlsInfo>()
        .unwrap()
        .peer_certificate()
        .unwrap();
    assert_eq!(peer, cert.to_der().unwrap());
    let trust = CertStore::builder().add_der_cert(peer).build().unwrap();
    let client = builder().tls_cert_store(trust.clone()).build().unwrap();
    assert!(client.get(&url).send().await.unwrap().status().is_success());

    let (other_cert, other_key) = self_signed();
    let other_addr = serve(&other_cert, &other_key).await;
    let other = Client::builder()
        .no_proxy()
        .resolve("wreq.test", other_addr)
        .tls_cert_store(trust.clone())
        .build()
        .unwrap();
    let other_url = format!("https://wreq.test:{}/", other_addr.port());
    assert!(other.get(other_url).send().await.unwrap_err().is_connect());

    // The certificate covers wreq.test but not the loopback IP address.
    let wrong_host = format!("https://{addr}/");
    assert!(
        client
            .get(&wrong_host)
            .send()
            .await
            .unwrap_err()
            .is_connect()
    );
    let skip_hostname = || Client::builder().no_proxy().tls_verify_hostname(false);
    let trusted = skip_hostname().tls_cert_store(trust).build().unwrap();
    assert!(
        trusted
            .get(&wrong_host)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let untrusted = skip_hostname().build().unwrap();
    assert!(
        untrusted
            .get(&wrong_host)
            .send()
            .await
            .unwrap_err()
            .is_connect()
    );
}
