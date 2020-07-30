// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use crate::system::SystemSettings;

/// infinitely performs http requests to cadvisor and put response into db
pub async fn metric_collector(settings: SystemSettings) {
    use tokio::time;
    use reqwest::Url;
    use tracing::{error, info};
    use chrono::Duration;
    use std::{fmt, collections::HashMap};
    use crate::{
        messages::metric_message::{MetricMessage, ContainerInfo},
        storage::MetricStore,
        system::{
            notification::{Sender, SendError, NotificationMessage},
            metric_alert::SystemCapacityObserver,
        },
    };

    enum MetricCollectionError {
        Reqwest(reqwest::Error),
        Io(reqwest::Error),
        DeserializeJson(serde_json::Error),
        StoreMessage(storage::StorageError),
        NotificationSend(SendError),
    }
    
    impl fmt::Display for MetricCollectionError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use MetricCollectionError::*;
    
            match self {
                &Reqwest(ref e) => write!(f, "error performing http request: {}", e),
                &Io(ref e) => write!(f, "io error during http request: {}", e),
                &DeserializeJson(ref e) => write!(f, "failed to deserialize json: {}", e),
                &StoreMessage(ref e) => write!(f, "failed to store message in database: {}", e),
                &NotificationSend(ref e) => write!(f, "failed to send notification: {}", e),
            }
        }
    }

    async fn fetch_and_store(
        url: &Url,
        storage: &MetricStore,
        observer: &mut SystemCapacityObserver,
        notifier: &mut Option<Sender>,
    ) -> Result<(), MetricCollectionError> {
        // perform http GET request 
        let r = reqwest::get(url.clone())
            .await
            .map_err(MetricCollectionError::Reqwest)?
            .text()
            .await
            .map_err(MetricCollectionError::Io)?;
        // deserialize the response as a json object, assume it is `ContainerInfo` map
        let info = serde_json::from_str::<HashMap<String, ContainerInfo>>(r.as_str())
            .map_err(MetricCollectionError::DeserializeJson)?;

        // find the first container that contains tezos node, assume there is single such container
        if let Some(container_info) = info.into_iter().find(|&(_, ref i)| i.tezos_node()) {
            // take stats from the `ContainerInfo` object, wrap it as `MetricMessage`
            // and show it to `SystemCapacityObserver` in order to determine if should show an alert
            let messages = container_info.1.stats
                .into_iter()
                .map(|x| {
                    let message = MetricMessage(x);
                    observer.observe(&message);
                    message
                })
                .collect();
            // if observer has some alert and we have some notifier, send the notification
            if let Some(notifier) = notifier {
                let alert = observer.alert();
                if !alert.is_empty() {
                    let message = alert.into_iter().fold(String::new(), |s, item| format!("{}{}\n", s, item));
                    notifier.send(&NotificationMessage::Warning(message))
                        .map_err(MetricCollectionError::NotificationSend)?;
                }
                let status = observer.status();
                if !status.is_empty() {
                    let message = status.into_iter().fold(String::new(), |s, item| format!("{}{}\n", s, item));
                    info!(machine_status = tracing::field::display(&message));
                    notifier.send(&NotificationMessage::Info(message))
                        .map_err(MetricCollectionError::NotificationSend)?;
                }
            }
            // write into db
            storage
                .store_message_array(messages)
                .map_err(MetricCollectionError::StoreMessage)?;
        }
        Ok(())
    }

    // prepare url to fetch statistics from docker containers
    // unwrap is safe because joining constant
    let url = settings.cadvisor_url
        .join("api/v1.3/docker")
        .unwrap();

    // login to messenger, it will provide object that can send alerts
    let messenger = settings
        .notification_cfg
        .channel
        .notifier()
        .map_err(|e|
            error!(error = tracing::field::display(&e), "failed to login to slack")
        )
        .ok();
    let mut sender = messenger.map(|m| m.sender(settings.notification_cfg.minimal_interval));

    tokio::spawn(async move {
        loop {
            // notifier is `Send` but not `Sync`
            // should clone it and drop after each iteration
            // it happens each `metrics_fetch_interval` few minute or so, minimal overhead
            let mut condition = settings.notification_cfg.alert_config.condition_checker();

            fetch_and_store(
                &url,
                settings.storage.metric(),
                &mut condition,
                &mut sender,
            )
                .await
                .unwrap_or_else(|e|
                    error!(error = tracing::field::display(&e), "failed to fetch and store metrics")
                );
            // this interval should be less equal to 
            // `--housekeeping_interval` of the cadvisor in the docker-compose.*.yml config
            let duration = settings.metrics_fetch_interval
                .to_std()
                .unwrap_or_else(|e| {
                    error!(error = tracing::field::display(&e), "bad config value `metrics_fetch_interval`");
                    Duration::minutes(1).to_std().unwrap()
                });
            time::delay_for(duration).await;
        }
    });
}
