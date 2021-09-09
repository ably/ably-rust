use super::http::Method;
use super::{Response, RestClient, Result};
use serde::Deserialize;

/// Ably Application statistics retrieved from [REST stats endpoint].
///
/// [REST stats endpoint]: https://docs.ably.io/rest-api/#stats
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Stats {
    pub interval_id: String,
    pub unit:        Unit,

    pub all:       Option<MessageTypes>,
    pub inbound:   Option<MessageTraffic>,
    pub outbound:  Option<MessageTraffic>,
    pub persisted: Option<MessageTypes>,

    pub connections: Option<ConnectionTypes>,
    pub channels:    Option<ResourceCount>,

    pub api_requests:   Option<RequestCount>,
    pub token_requests: Option<RequestCount>,

    pub push: Option<Push>,

    pub xchg_producer: Option<XchgMessages>,
    pub xchg_consumer: Option<XchgMessages>,

    pub peak_rates: Option<Rates>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Unit {
    Minute,
    Hour,
    Day,
    Month,
}

impl Default for Unit {
    fn default() -> Self {
        Unit::Minute
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MessageCount {
    pub count:   f64,
    pub data:    f64,
    pub failed:  f64,
    pub refused: f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ResourceCount {
    pub peak:    f64,
    pub min:     f64,
    pub mean:    f64,
    pub opened:  f64,
    pub failed:  f64,
    pub refused: f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RequestCount {
    pub failed:    f64,
    pub refused:   f64,
    pub succeeded: f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MessageTypes {
    pub all:      MessageCount,
    pub messages: MessageCount,
    pub presence: MessageCount,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ConnectionTypes {
    pub all:   ResourceCount,
    pub plain: ResourceCount,
    pub tls:   ResourceCount,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MessageTraffic {
    pub all:            MessageTypes,
    pub realtime:       MessageTypes,
    pub rest:           MessageTypes,
    pub webhook:        MessageTypes,
    pub push:           MessageTypes,
    pub external_queue: MessageTypes,
    pub shared_queue:   MessageTypes,
    pub http_event:     MessageTypes,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Push {
    pub messages:         f64,
    pub notifications:    PushNotifications,
    pub direct_publishes: f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PushNotifications {
    pub invalid:    f64,
    pub attempted:  PushTransportCount,
    pub successful: PushTransportCount,
    pub failed:     PushNotificationFailures,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PushTransportCount {
    pub total: f64,
    pub gcm:   f64,
    pub fcm:   f64,
    pub apns:  f64,
    pub web:   f64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PushNotificationFailures {
    pub retriable: PushTransportCount,
    pub final_:    PushTransportCount,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct XchgMessages {
    pub all:           MessageTypes,
    pub producer_paid: MessageDirections,
    pub consumer_paid: MessageDirections,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MessageDirections {
    pub all:      MessageTypes,
    pub inbound:  MessageTraffic,
    pub outbound: MessageTraffic,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Rates {
    pub messages:       f64,
    pub api_requests:   f64,
    pub token_requests: f64,
    pub reactor:        ReactorRates,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReactorRates {
    pub http_event: f64,
    pub amqp:       f64,
}

/// A builder to construct a REST stats request.
pub struct StatsBuilder {
    client: RestClient,
    params: Option<Vec<(String, String)>>,
}

impl StatsBuilder {
    pub fn new(client: RestClient) -> StatsBuilder {
        StatsBuilder {
            client,
            params: None,
        }
    }

    pub fn start(mut self, interval: &str) -> StatsBuilder {
        let param = ("start".to_string(), interval.to_string());

        match self.params {
            Some(ref mut params) => params.push(param),
            None => self.params = Some(vec![param]),
        }

        self
    }

    pub fn end(mut self, interval: &str) -> StatsBuilder {
        let param = ("end".to_string(), interval.to_string());

        match self.params {
            Some(ref mut params) => params.push(param),
            None => self.params = Some(vec![param]),
        }

        self
    }

    pub fn forwards(mut self) -> StatsBuilder {
        let param = ("direction".to_string(), "forwards".to_string());

        match self.params {
            Some(ref mut params) => params.push(param),
            None => self.params = Some(vec![param]),
        }

        self
    }

    pub async fn send(self) -> Result<Response> {
        self.client
            .request(Method::GET, "/stats", self.params, None::<()>, None)
            .await
    }
}
