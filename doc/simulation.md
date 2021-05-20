Data logging and playback
=========================

It can be useful to run bitcoind, or patches applied to bitcoind (eg PR's that
need to be tested) on fixed sets of historical data.  For example, this might
be done to help test code correctness, measure performance impact, or perform
research on the bitcoin network.

The nature of the bitcoin p2p network is that there is no canonical data set of
traffic on the network.  However, it can be useful to log the data received by
a node, and simulate bitcoind's behavior on the recorded data.  This branch
supports both data logging and this simulated playback.

 * Data logging

    To record historical data, run `bitcoind` with `-dlogdir=<directory name>`.
    This command-line argument enables data logging, and files with names like
    `block.<YYYYMMDD>`, `tx.<YYYYMMDD>`, `headers.<YYYYMMDD>`, `cmpctblock.<YYYYMMDD>`,
    and `blocktxn.<YYYYMMDD>` will be written to the specified directory.
    These files will roll automatically at midnight of the next day.

 * Simulation

    To run on historical recorded data, bitcoind will need a bitcoin data directory
    that has been correctly snapshotted as of the start time of the simulation.
    Performing that snapshotting is outside the scope of this branch, but it is
    important that the UTXO state and the headers chain be valid exactly as-of the
    start time of the simulation.

    Given such a snapshot, bitcoind can be run in historical mode by specifying the
    `-simulation` argument (which disables the networking thread, so bitcoind will not
    connect out to the p2p network), the `-simdatadir` argument (where the historical
    recorded data can be found, in files named `block.<YYYYMMDD>`, etc), the `-start`
    and `-end` arguments (to specify the starting and ending date of the simulation),
    and optionally the `-loadmempool` argument (to specify whether to load a starting
    mempool from the datadir).

