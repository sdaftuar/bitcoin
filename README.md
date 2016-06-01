Bitcoin Core - data logging + simulation
========================================

This patchset adds support for logging data (blocks, transactions, headers
messages) and for simulating bitcoind by using logged data.

To log data, start up bitcoind with `-dlogdir=<dirname>`, and data logging will
be enabled, with files written to the given directory, with filenames like
`block.<date>`, `tx.<date>`, etc.

To run a simulation using the logged data, start with a snapshot of a bitcoin
datadir as of midnight of the day the simulation should start from, and then
run bitcoind with `-simulation -simdatadir=<dir> -start=<YYYYMMDD>
-end=<YYYYMMDD> -loadmempool=0`.

Default end date is the start date.

Note that loading the mempool from the logged data is currently broken, so
-loadmempool=0 is recommended to avoid trying.

Getting an appropriate starting snapshot of the bitcoin datadir is left as
an exercise to the reader...  Once you have one, subsequent snapshots can be
created using the simulation itself.
