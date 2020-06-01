# DoHlyzer
Set of tools to capture HTTPS traffic, extract statistical and time-series features from it, and analyze them with 
a focus on detecting and characterizing DoH (DNS-over-HTTPS) traffic. 

## Acknowledgement

This project has been made possible through funding from Canadian Internet Registration Authority (CIRA).

## Modules

DoHlyzer currently consists of several independent modules, each carrying some of the functionality needed to analyze
the data for DoH flows.

### Meter
Meter module is responsible for:

1. Capturing HTTPS packets from network interfaces or reading input PCAP files
2. Grouping packets into flows by their source and destination addresses and ports
3. Extracting features for traffic analysis, including statistical and time-series features  

### Prerequisites

Python packages needed for running DoHlyzer are listed in `requirements.txt` file. You can install them 
(preferably in virtualenv) by:
```
pip install -r requirements.txt
```

## Deployment

Each of the modules come with their own README files to describe how they can be used.

## Contributing

The project is not currently in development but any contribution is welcome in form of pull requests.

## Project Team members

* [**Arash Habibi Lashkari:**](https://www.cs.unb.ca/~alashkar/) Founder and Project Leader
* [**Mohammadreza MontazeriShatoori:**](https://github.com/mr-montazeri) Research and Development
* [**Gurdip Kaur:**](https://www.linkedin.com/in/gurdip-kaur-738062164/) Research
* [**Logan Davidson:**](https://github.com/ladavids) Development
