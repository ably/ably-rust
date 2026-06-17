use std::env;

use serde::Serialize;

use ably::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let key = env::var("ABLY_API_KEY").expect("ABLY_API_KEY env var must be set");

    let client = ably::Rest::new(&key)?;

    let channel = client.channels().get("rust-example").await;

    println!("Publishing a string");
    match channel
        .publish()
        .await
        .name("string")
        .string("a string")
        .send()
        .await
    {
        Ok(_) => println!("String published!"),
        Err(err) => println!("Error publishing message: {}", err),
    }

    println!("Publishing a JSON object");
    #[derive(Serialize)]
    struct Point {
        x: i32,
        y: i32,
    }
    let point = Point { x: 3, y: 4 };
    match channel
        .publish()
        .await
        .name("json")
        .json(point)
        .send()
        .await
    {
        Ok(_) => println!("JSON object published!"),
        Err(err) => println!("Error publishing message: {}", err),
    }

    println!("Publishing binary data");
    let data = vec![0x01, 0x02, 0x03, 0x04];
    match channel
        .publish()
        .await
        .name("binary")
        .binary(data)
        .send()
        .await
    {
        Ok(_) => println!("Binary data published!"),
        Err(err) => println!("Error publishing message: {}", err),
    }

    Ok(())
}
