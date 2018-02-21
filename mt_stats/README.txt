--- Description ---

This folder contains information needed to run the moneTor statistics colleciton
functionality. Tor nodes calculate a fixed set of statistics in RAM during
within the Tor executable. Results from a single node/window are published to
mt_stats/published. Periodically, a central server elsewhere aggregate the
published statistics from all recording nodes and delete the local copies.

--- Instructions ---

At each Tor node, set the torrc MoneTorStatistics field. MoneTorStatistics is
a decimal from [0 - 1] that encodes the random fraction of circuits that will
be recorded.

At a separate central server, schedule a cron job (hourly is recommended) for
mt_stats/scripts/central.sh. The outputed information will be continously
updated for each port within the mt_stats/aggregate/ folder.
