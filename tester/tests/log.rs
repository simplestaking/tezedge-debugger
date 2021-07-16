// Copyright (c) SimpleStaking, Viable Systems and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezedge_recorder::tables::node_log;

pub async fn get_log(params: &str) -> Result<Vec<node_log::ItemWithId>, serde_json::error::Error> {
    let res = reqwest::get(&format!("http://localhost:17742/v3/logs?{}", params))
        .await.unwrap()
        .text()
        .await.unwrap();
    serde_json::from_str(&res)
}

#[tokio::test]
async fn level() {
    use tezedge_recorder::tables::node_log::LogLevel;

    struct TestCase {
        query: &'static str,
        predicate: fn(LogLevel) -> bool,
    }

    impl TestCase {
        async fn run(&self, forward: bool) {
            let direction = if forward { "direction=forward&cursor=0" } else { "direction=backward" };
            let params = format!("limit=1000&log_level={}&{}", self.query, direction);
            let items = get_log(&params).await.unwrap();
            assert!(!items.is_empty());
            for item in items {
                assert!((self.predicate)(item.level));
            }
        }
    }

    let cases = [
        TestCase { query: "info", predicate: |l| matches!(l, LogLevel::Info) },
        TestCase { query: "warn", predicate: |l| matches!(l, LogLevel::Warning) },
        TestCase { query: "error", predicate: |l| matches!(l, LogLevel::Error) },

        TestCase { query: "warn,error", predicate: |l| matches!(l, LogLevel::Warning | LogLevel::Error) },
        TestCase { query: "error,info", predicate: |l| matches!(l, LogLevel::Error | LogLevel::Info) },
        TestCase { query: "info,warn", predicate: |l| matches!(l, LogLevel::Info | LogLevel::Warning) },
    ];

    for case in &cases {
        case.run(false).await;
        case.run(true).await;
    }
}

#[tokio::test]
async fn pagination() {
    async fn request_cursor(cursor: usize, result: usize) {
        let params = format!("cursor={}&limit=1000", cursor);
        let items = get_log(&params).await.unwrap();
        assert_eq!(items.len(), 1000);
        for (n, item) in items.into_iter().enumerate() {
            assert_eq!((item.id as usize) + n, result);
        }
    }

    let last = get_log("limit=1").await.unwrap();
    let mut last_id = last.last().unwrap().id as usize;

    // deliberate out of range, should give last
    request_cursor(last_id * 2, last_id).await;

    loop {
        request_cursor(last_id, last_id).await;
        if last_id >= 1000 {
            last_id -= 1000;
        } else {
            break;
        }
    }

    request_cursor(1234, 1234).await;
}

#[tokio::test]
async fn timestamp() {
    struct TestCase {
        shift: u64,
        expected: usize,
        forward: bool,
    }

    impl TestCase {
        async fn run(self) {
            let time = 1626264000 + self.shift;
            let direction = if self.forward { "forward" } else { "backward" };
            let params = format!("timestamp={}&limit=500&direction={}", time, direction);
            let items = get_log(&params).await.unwrap();
            assert_eq!(items.len(), self.expected);
            let mut time = time;
            for item in items {
                let this = (item.timestamp / 1_000_000_000) as u64;
                if self.forward {
                    assert!(this > time);
                } else {
                    assert!(this <= time);
                }
                time = this;
            }
        }
    }

    let test_cases = vec![
        TestCase { shift: 321, expected: 322, forward: false },
        TestCase { shift: 321, expected: 500, forward: true },
        TestCase { shift: 6789, expected: 500, forward: false },
        TestCase { shift: 6789, expected: 500, forward: true },
        TestCase { shift: 9876, expected: 500, forward: false },
        TestCase { shift: 9876, expected: 9999 - 9876, forward: true },
    ];

    for test_case in test_cases {
        test_case.run().await;
    }
}
