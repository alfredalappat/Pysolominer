# Pysolominer

A tiny, single-threaded **solo Bitcoin miner** in pure Python (Stratum v1, no dependencies).

Think of it as a **digital lottery**: every hash is a ticket, and one lucky hash could win an entire block. It could be your very first hash. **No fee to buy this lottery** - just run it and let it play.


## Features

- Real Stratum v1 mining. Every event prints as its own row: new job, new block on the network, accepted / rejected share, connection lost / reconnected
- A statistics block (hashrate, pool / network / accepted difficulty, shares, best share, block height) is printed every `--refresh` seconds
- `CONNECTION LOST` screen and automatic reconnect when the pool connection drops
- `log.txt` next to the script: created if missing, cleaned and restarted from the top at 5 MB
- Single thread, standard library only, Python 3.8+ (Windows 10+, Linux, macOS)

## Quick start

```bash
python pysolominer.py --address <YOUR_BITCOIN_ADDRESS> --url <POOL>
python pysolominer.py --selftest   # check hashing against the genesis block
```

Example pools:

```
stratum.ckpool.org:3333
public-pool.io:3333
```

## Sample output

```
09:40:19  INFO   Connected to pool.example.com:3333
09:40:19  JOB    New job 4f2a (first job) | height 850000
09:40:23  JOB    New job 4f2b (update) | height 850000
09:40:26  BLOCK  New block on network | now mining height 850001
09:40:26  JOB    New job 4f2c (clean) | height 850001
09:40:31  SHARE  Accepted share, diff 1.000 K
09:40:35  LOST   Connection lost: pool closed the connection
09:40:38  INFO   Reconnected after 00h 00m 03s

---- STATISTICS 09:40:39 ---------------------------
  Status                CONNECTED
  Hashrate              412.30 kH/s
  Pool difficulty       1.000 K
  Network difficulty    126.41 T
  ...
```

## Options

| Option | Description |
|---|---|
| `--address` | Your Bitcoin address - any block reward is paid here (prompted if omitted) |
| `--url` | Pool `host:port`, with or without `stratum+tcp://` (prompted if omitted) |
| `--worker` | Optional worker name |
| `--password` | Pool password (default `x`) |
| `--refresh` | Seconds between statistics blocks (default `30`, minimum `1`) |
| `--selftest` | Run the built-in hash test and exit |

## Run on android

You can also run pysolominer on Android smartphones using Pydroid 3.
No root access is required. Install Pydroid 3, set up Python, download the miner, and run it from the terminal.
Your Android phone can participate in Bitcoin solo mining just like a desktop computer.

## Support the project 

If you find this project useful, please consider giving it a ⭐

## Donation

If this lottery ever pays out, a donation is welcome but never required:

👉 BTC = `bc1qjqmgkuu4qefgwpdq24dvmz60pvjnn7egvc4zke`

