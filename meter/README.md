# DoHMeter
This module can read the captured network packets and aggregate them into traffic flows. Furthermore, based on the requested mode, it extracts statistical or time-series features from the flows.
 
## Usage
There are two options that you need to specify when running DoHMeter: input and mode.

Input can be specified by `-n <iface>` for capturing online traffic (`iface` being the network interface used) or 
`-f <pcap_file>` for reading packets from a PCAP file. Online traffic captures should be interrupted manually (by ^C).

The two modes available when running DoHMeter indicate which type of features DoHMeter should extract.
### Statistical Features
This mode is activated by using `-c` option and extracts statistical features from the input traffic. Results are saved 
in a CSV file, the path of which should be specified by user.

Example:

```bash
python3 dohlyzer.py -n eth0 -c ./output.csv
```

See `meter.flow.Flow.get_data` for the list of features extracted in this CSV file.

### Time-series Features
This mode is activated by the `-s` switch and generate a sequence of clumps saved in JSON format. The output path in
this mode should be a directory containing two subdirectories: doh & ndoh. Each flow is saved in a file indicated by
source and destination addresses and ports, in the corresponding subdirectory. The contents of the file is a list of 
sequences. each sequence is a list of clumps. Each clump is a list of 5 parameters of a clump: Inter-arrival Time, 
Duration, Size, Number of Packets, and Direction.

Example:
```bash
# Preparing the output directories
mkdir output
mkdir -p output/doh/
mkdir -p output/ndoh/

# Feature extraction
python3 dohlyzer.py -n eth0 -s ./output/
```
