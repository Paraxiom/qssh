//! Regression tests for the in-band rekey (protocol 0.2).
//!
//! The July 2026 failure: a separate rekey task read from the transport
//! concurrently with the data reader, so each stole frames from the other,
//! and both sides switched both keys at once, so in-flight frames were
//! decrypted under the wrong epoch ("failed to read frame length: early eof"
//! on busy tunnels at every rotation). These tests drive rekeys from both
//! sides while both directions carry ordered traffic and check that nothing
//! is lost, reordered or rejected.

use qssh::crypto::SymmetricCrypto;
use qssh::transport::{initial_epoch_secret, ChannelMessage, DisconnectMessage, Message, Transport};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Duration};

/// Two transports over a real loopback TCP connection, keyed the way the
/// handshake keys them (client sends with the client write key, server with
/// the server write key) and seeded with the same epoch secret.
async fn pair() -> (Transport, Transport) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::join!(
        async { listener.accept().await.unwrap().0 },
        TcpStream::connect(addr)
    );
    let connected = connected.unwrap();
    let cw = [0x11u8; 32];
    let sw = [0x22u8; 32];
    let client = Transport::new_bidirectional(
        connected,
        SymmetricCrypto::from_shared_secret(&cw).unwrap(),
        SymmetricCrypto::from_shared_secret(&sw).unwrap(),
    );
    let server = Transport::new_bidirectional(
        accepted,
        SymmetricCrypto::from_shared_secret(&sw).unwrap(),
        SymmetricCrypto::from_shared_secret(&cw).unwrap(),
    );
    let epoch = initial_epoch_secret(&cw, &sw);
    client.set_epoch_secret(epoch).await;
    server.set_epoch_secret(epoch).await;
    (client, server)
}

/// The single reader a real client or server runs: it sees data frames and
/// never sees rekey control frames, which the transport consumes.
fn spawn_reader(t: Transport, sink: Arc<Mutex<Vec<u64>>>) -> JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        loop {
            match t.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { data, .. })) => {
                    let n = u64::from_be_bytes(data[..8].try_into().unwrap());
                    sink.lock().await.push(n);
                }
                Ok(Message::Disconnect(_)) => return Ok(()),
                Ok(Message::RekeyInit(_)) | Ok(Message::RekeyReply(_)) | Ok(Message::NewKeys) => {
                    return Err("rekey control frame leaked to the application".into());
                }
                Ok(_) => {}
                Err(e) => return Err(format!("{e}")),
            }
        }
    })
}

async fn send_numbered(t: &Transport, count: u64, pause_every: u64) {
    for i in 0..count {
        t.send_message(&Message::Channel(ChannelMessage::Data {
            channel_id: 1,
            data: i.to_be_bytes().to_vec(),
        }))
        .await
        .unwrap();
        if pause_every > 0 && i % pause_every == 0 {
            sleep(Duration::from_micros(200)).await;
        }
    }
}

fn disconnect() -> Message {
    Message::Disconnect(DisconnectMessage {
        reason_code: 0,
        description: "test done".into(),
    })
}

#[tokio::test]
async fn rekeys_from_both_sides_under_full_duplex_load_lose_nothing() {
    timeout(Duration::from_secs(60), async {
        let (client, server) = pair().await;
        let to_server = Arc::new(Mutex::new(Vec::new()));
        let to_client = Arc::new(Mutex::new(Vec::new()));
        let server_reader = spawn_reader(server.clone(), to_server.clone());
        let client_reader = spawn_reader(client.clone(), to_client.clone());

        const N: u64 = 3000;
        let c = client.clone();
        let client_writer = tokio::spawn(async move { send_numbered(&c, N, 7).await });
        let s = server.clone();
        let server_writer = tokio::spawn(async move { send_numbered(&s, N, 5).await });

        // Rotate three times from the client and once from the server while
        // both writers are busy. Each rotation must complete in both directions.
        for i in 0..3 {
            sleep(Duration::from_millis(15)).await;
            let done = client.initiate_rekey().await.unwrap();
            timeout(Duration::from_secs(10), done)
                .await
                .unwrap_or_else(|_| panic!("client rekey {} timed out", i))
                .expect("client rekey aborted");
        }
        sleep(Duration::from_millis(15)).await;
        let done = server.initiate_rekey().await.unwrap();
        timeout(Duration::from_secs(10), done)
            .await
            .expect("server rekey timed out")
            .expect("server rekey aborted");

        client_writer.await.unwrap();
        server_writer.await.unwrap();
        client.send_message(&disconnect()).await.unwrap();
        server.send_message(&disconnect()).await.unwrap();
        server_reader.await.unwrap().expect("server reader failed");
        client_reader.await.unwrap().expect("client reader failed");

        let expected: Vec<u64> = (0..N).collect();
        assert_eq!(*to_server.lock().await, expected, "client->server stream lost or reordered frames");
        assert_eq!(*to_client.lock().await, expected, "server->client stream lost or reordered frames");
        assert_eq!(client.rekey_count(), 4);
        assert_eq!(server.rekey_count(), 4);
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn rekey_completes_on_an_idle_connection_and_traffic_resumes_after() {
    timeout(Duration::from_secs(30), async {
        let (client, server) = pair().await;
        let to_server = Arc::new(Mutex::new(Vec::new()));
        let to_client = Arc::new(Mutex::new(Vec::new()));
        let server_reader = spawn_reader(server.clone(), to_server.clone());
        let client_reader = spawn_reader(client.clone(), to_client.clone());

        let done = client.initiate_rekey().await.unwrap();
        timeout(Duration::from_secs(10), done).await.unwrap().unwrap();
        assert_eq!(client.rekey_count(), 1);

        // Everything after the rotation rides the new epoch in both directions.
        send_numbered(&client, 50, 0).await;
        send_numbered(&server, 50, 0).await;
        client.send_message(&disconnect()).await.unwrap();
        server.send_message(&disconnect()).await.unwrap();
        server_reader.await.unwrap().unwrap();
        client_reader.await.unwrap().unwrap();
        assert_eq!(*to_server.lock().await, (0..50).collect::<Vec<u64>>());
        assert_eq!(*to_client.lock().await, (0..50).collect::<Vec<u64>>());
        assert_eq!(server.rekey_count(), 1);
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn a_second_rekey_cannot_start_while_one_is_in_flight() {
    timeout(Duration::from_secs(30), async {
        let (client, _server) = pair().await;
        // No server reader is running, so the first rekey stays pending.
        let _pending = client.initiate_rekey().await.unwrap();
        let err = client.initiate_rekey().await.err().expect("second rekey must be refused");
        assert!(format!("{err}").contains("already in progress"), "{err}");
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn new_keys_without_a_pending_rekey_is_a_protocol_error() {
    timeout(Duration::from_secs(30), async {
        let (client, server) = pair().await;
        server.send_message(&Message::NewKeys).await.unwrap();
        let err = client
            .receive_message::<Message>()
            .await
            .err()
            .expect("stray NewKeys must be rejected");
        assert!(format!("{err}").contains("NewKeys without a pending rekey"), "{err}");
    })
    .await
    .expect("test timed out");
}

#[test]
fn epoch_seed_is_role_independent_and_bound_to_both_keys() {
    let a = initial_epoch_secret(&[1u8; 32], &[2u8; 32]);
    assert_eq!(a, initial_epoch_secret(&[1u8; 32], &[2u8; 32]));
    assert_ne!(a, initial_epoch_secret(&[2u8; 32], &[1u8; 32]));
    assert_ne!(a, initial_epoch_secret(&[1u8; 32], &[3u8; 32]));
}
