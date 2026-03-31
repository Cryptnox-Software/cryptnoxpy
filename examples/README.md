# Cryptnox SDK Examples

This directory contains standalone examples demonstrating real-world usage of the Cryptnox SDK with various protocols and platforms. Each example is self-contained and includes its own detailed documentation.

## Prerequisites

The following are required for all examples:

| Component | Details |
|-----------|---------|
| **Hardware** | Cryptnox card (Basic G1 or NFT) initialized with a PIN, and a PC/SC-compatible smart card reader |
| **Python** | >= 3.11, <= 3.14 |
| **SDK** | `pip install cryptnox-sdk-py` (or installed from source) |

Additional dependencies specific to each example are listed in that example's README.

## Available Examples

| Example | Description |
|---------|-------------|
| [xrp_transaction](xrp_transaction/README.md) | Sign and submit XRP Ledger payment transactions using the card for secure key storage and ECDSA signing |

## How to Run an Example

1. **Clone the repository** (if not already done):

   ```bash
   git clone https://github.com/Cryptnox-Software/cryptnox-sdk-py.git
   cd cryptnox-sdk-py
   ```

2. **Install the SDK**:

   ```bash
   pip install .
   ```

3. **Navigate to the example directory**:

   ```bash
   cd examples/<example_name>
   ```

4. **Install example-specific dependencies** as listed in the example's README.

5. **Run the example script**:

   ```bash
   python <example_name>.py --pin <PIN> [options]
   ```

   Refer to the example's README for the full list of available options.

## Adding New Examples

Each example should follow the established conventions:

- Place it in its own subdirectory under `examples/`
- Include an `__init__.py` to make it an importable package
- Provide a main executable script named after the example
- Include a `README.md` covering requirements, quick start, how it works, and command-line options
