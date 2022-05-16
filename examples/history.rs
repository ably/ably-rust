use std::env;

use futures::StreamExt;

use ably::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let key = env::var("ABLY_API_KEY").expect("ABLY_API_KEY env var must be set");

    let client = ably::Rest::new(&key)?;

    let channel = client.channels().get("rust-example");

    // Publish 10 messages
    for n in 1..11 {
        println!("Publishing message {}", n);
        channel
            .publish()
            .string(format!("message {}", n))
            .send()
            .await?;
    }

    // Retrieve the history
    let mut pages = channel.history().pages();
    while let Some(Ok(page)) = pages.next().await {
        let msgs = page.items().await?;
        println!("Received page of {} messages", msgs.len());
        for msg in msgs {
            println!("data = {:?}", msg.data);
        }
    }

    Ok(())
}
