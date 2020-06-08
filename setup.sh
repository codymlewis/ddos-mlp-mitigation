#!/bin/sh

git submodule update --init --recursive &&
        cd dos-attacks &&
        cargo build --release
