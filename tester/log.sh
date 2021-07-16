#!/usr/bin/env bash

function fail {
    kill -SIGTERM $RECORDER_PID
    exit 1
}

./target/none/release/tezedge-recorder &
export RECORDER_PID=$!
sleep 2
cargo +nightly-2021-03-23 run -p tester --release -- first # populate first half of db
cargo +nightly-2021-03-23 test -p tester --tests --release -- pagination level || fail
kill -SIGTERM $RECORDER_PID
sleep 2
./target/none/release/tezedge-recorder &
export RECORDER_PID=$!
sleep 2
cargo +nightly-2021-03-23 test -p tester --tests --release -- pagination level || fail
cargo +nightly-2021-03-23 run -p tester --release -- second # populate second half of db
cargo +nightly-2021-03-23 test -p tester --tests --release -- pagination level timestamp || fail
kill -SIGTERM $RECORDER_PID
sleep 2
./target/none/release/tezedge-recorder &
export RECORDER_PID=$!
sleep 2
cargo +nightly-2021-03-23 test -p tester --tests --release -- pagination level timestamp || fail
kill -SIGTERM $RECORDER_PID
sleep 2
