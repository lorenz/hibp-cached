# hibp-cached
*A smart cache server for HIBP breached passwords*

If you want to use the Have I Been Pwned breached password database but do not
want to query their service directly, be that for latency, privacy or
availability concerns, this project is for you. It provides the exact same API
as the official HIBP v3 Breached Passwords service, but backed by a local cache
which is automatically downloaded and continually kept up-to-date. You can even
chain multiple hibp-cached instances to decrease load on the official API.

## Installation
With an installed Go toolchain, you can run
```
go install git.dolansoft.org/lorenz/hibp-cached@latest
```
which makes the hibp-cached binary available.

Alternatively there is a Dockerfile in the repo which can be used without an
installed Go toolchain.

## User's Guide
The current database is around 16GiB and grows at approximately 1GiB a year,
but this can vary wildly. I'd recommend to have at least 25GiB of free space.

Once started for the first time, it creates the `data` directory in its working
directory and the cache database file in there. Then it begins downloading
ranges from the configured `--upstream-url`, by default the official instance,
at a rate configured by `--fill-rps`, by default 100 requests per second.
During that time it serves 404 responses to clients requesting ranges not yet
downloaded. The progress of this process can be monitored via the
`fetch_position` Prometheus metric exposed on port 8081. The download process
is checkpointed and can be aborted and restarted at will, at 100 RPS it takes
around 3 hours.

As soon as all ranges are cached locally, the `initial_fill_done` metric gauge
goes to 1 and the `/ready` endpoint on port 8081 starts returning 200. At that
point the request rate drops to `--refresh-rps`, by default 0.4 (i.e. 1 request
every 2.5s) which are used to check for updated ranges. The default setting
achieves around 1 full refresh every month.

The API is being served on port 8080.

## Monitoring
A Prometheus/OpenMetrics compatible endpoint is available on port 8081 on path
`/metrics`. The following custom metrics are available:

### fetch_position
The filling and updating process is done in a ring-like fashion, starting at
the beginning (00000) up to the end (fffff) and then wraps around to the start.
This gauge shows on a scale from 0 to 1 where the process is currently at.
It's recommended to alert on this being stuck for ~1 day.

### in_flight_request_brake
Request issuance and concurrency are controlled to achieve the configured RPS,
but in case requests take more than 1s on average across the currently
in-flight ones, something is likely congested. To avoid extreme congestion and
subsequent misbehavior, this brake is applied which throttles request issuance
to stay under the 1s limit. If this counter rises aggressively, consider
reducing the configured RPS. This value is mostly relevant while filling
initially.

### initial_fill_done
Zero while not all ranges are cached yet, switches to 1 once all are cached.
Does currently never switch back to zero again.

### checkpoints_total
Counter of all checkpoints/commits to the bbolt database, by result.
If the error counter increases, check available disk space as well as storage
health.
It's recommended to alert on a rising error counter.

### upstream_requests_total
Counter of all requests made to upstream by result.

### http_requests_total
Counter of all requests made to the cache by status code.

## Roadmap
* A changefeed-based API for efficient change detection when chaining.
* A bulk API which provides larger, binary chunks.

## License
MIT