use std::env;

use futures::StreamExt;

use ably::{error::ErrorCode, Error, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let key = env::var("ABLY_API_KEY").expect("ABLY_API_KEY env var must be set");

    let client = ably::Rest::new(&key)?;

    // Initialize a channel with cipher parameters so that published messages
    // get encrypted.
    let cipher = ably::crypto::CipherParams::default();
    let channel = client
        .channels()
        .name("rust-example")
        .cipher(cipher.clone())
        .get();

    // Publish a message as normal.
    println!("Publishing a string");
    match channel
        .publish()
        .name("test")
        .string("a string")
        .send()
        .await
    {
        Ok(_) => println!("String published!"),
        Err(err) => println!("Error publishing message: {}", err),
    }

    // Retrieve the message from history using another client which doesn't
    // have the cipher params.
    let client = ably::Rest::new(&key)?;
    let channel = client.channels().name("rust-example").get();
    let page = channel.history().pages().next().await.unwrap()?;
    let msg = page.items().await?.pop().expect("Expected a message");
    println!("Retrieved message from history: data = {:?}", msg.data);

    // The data should be binary, and decrypting it should return the string we
    // published.
    println!("Decrypting the data");
    let mut data = match msg.data {
        ably::Data::Binary(data) => data.into_vec(),
        _ => return Err(Error::new(ErrorCode::BadRequest, "Expected binary data")),
    };
    let decrypted = cipher.decrypt(&mut data)?;
    println!("Decrypted = {:?}", decrypted);
    assert_eq!(decrypted, "a string".as_bytes());

    Ok(())
}
