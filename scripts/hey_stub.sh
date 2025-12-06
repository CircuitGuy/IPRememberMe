#!/usr/bin/env sh
# Minimal stub for hey output in CSV (response-time in seconds).
cat <<'CSV'
response-time,DNS+dialup,DNS,Request-write,Response-delay,Response-read,status-code,offset
0.0500,0,0,0,0.05,0,200,0
0.0600,0,0,0,0.06,0,200,0.05
0.0400,0,0,0,0.04,0,200,0.11
CSV
