# WSN Authentication Protocol Simulation

This project is a simple Python implementation of a WSN authentication scheme
(inspired by the ACM TCPS paper you provided). It is **for learning/testing only**
and is **not** secure for real-world use.

## Requirements

- Python 3.10+
- No external dependencies (only standard library)

## How to run

```bash
python main.py
```

You’ll see a small demo:

1. Setup system (GWN, RSA keys, etc.)
2. Register one sensor (`S1`)
3. Register user (`alice`, password `password123`)
4. Run one full login+authentication with `alice` and `S1`
5. Print whether authentication succeeded and the derived session key.

## Running tests

If you have `pytest` installed:

```bash
pytest
```

or you can run the test file directly:

```bash
python -m tests.test_protocol
```
