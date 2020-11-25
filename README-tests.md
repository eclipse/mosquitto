# Tests

## Running

The Mosquitto test suite can be invoked using either of

```
make test
make check
```

The tests run in series and due to the nature of some of the tests being made
can take a while.

## Parallel Tests

To run the tests with some parallelism, use

```
make ptest
```

This runs up to 20 tests in parallel at once, yielding much faster overall run
time at the expense of having up to 20 instances of Python running at once.
This is not a particularly CPU intensive option, but does require more memory
and may be unsuitable on e.g. a Raspberry Pi.

## Dependencies

The tests require Python 3 and CUnit to be installed.
