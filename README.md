# Project Setup Instructions

This document provides step-by-step instructions for setting up the required environment and running the necessary commands for **Question 1** and **Question 2**.

## Prerequisites

Before proceeding, ensure you have the following tools installed:

- **`pip`**: For installing Python libraries
- **`sudo`**: For installing system dependencies

## Step 1: Install System Dependencies

You need to install **`tcpreplay`**, a tool used to replay network traffic from `.pcap` files. 

Run the following commands to update your package list and install `tcpreplay`:

```bash
sudo apt update
sudo apt install -y tcpreplay
```

## Step 2: Install Python Libraries

The following Python libraries are required:

- `scapy` (for packet crafting and analysis)
- `pandas` (for data manipulation and analysis)
- `numpy` (for numerical operations)
- `matplotlib` (for data visualization)

To install them, run:

```bash
sudo pip install scapy pandas numpy matplotlib
```

## Step 3: Run the Commands

You will need to run the scripts in two different terminal windows to simulate the necessary operations for each question.

### For **Question 1**:

1. **In the first terminal**, run the `sniffer2.py` script using the following command:

    ```bash
    sudo python3 sniffer2.py
    ```

2. **In the second terminal**, run the `tcpreplay` command to replay network traffic from the `7.pcap` file:

    ```bash
    sudo tcpreplay -i eth0 --pps=10000 7.pcap
    ```

3. This will give the output for **Question 1** in the terminal.

### For **Question 2**:

1. **In the first terminal**, run the `part_2.py` script using the following command:

    ```bash
    sudo python3 part_2.py
    ```

2. **In the second terminal**, run the `tcpreplay` command to replay network traffic from the `7.pcap` file:

    ```bash
    sudo tcpreplay -i eth0 --pps=10000 7.pcap
    ```

3. This will give the output for **Question 2** in the terminal.

## Notes

- Ensure that the `.pcap` file (`7.pcap`) is available in the directory where the script is run.
- The `eth0` network interface is used in the commands; make sure that this matches your system's network interface. You can check your interface using `ifconfig` or `ip a`.
- You may need to run the commands with `sudo` for permissions, depending on your system configuration.
