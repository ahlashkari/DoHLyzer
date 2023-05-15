# DoHlyzer
Set of tools to capture HTTPS traffic, extract statistical and time-series features from it, and analyze them with 
a focus on detecting and characterizing DoH (DNS-over-HTTPS) traffic. 

## Acknowledgement

This project has been made possible through funding from the Canadian Internet Registration Authority (CIRA) fron July 2019 to Jyly 2020.

## Modules

DoHlyzer currently consists of several independent modules, each carrying some of the functionality needed to analyze
the data for DoH flows.

### Meter
DoHMeter module is responsible for:

1. Capturing HTTPS packets from network interfaces or reading input PCAP files
2. Grouping packets into flows by their source and destination addresses and ports
3. Extracting features for traffic analysis, including statistical and time-series features  

### Analyzer
This module can be used to create the proposed DNN models and benchmark them against the aggregated clumps file that can be created by the Meter module.


### Visualizer
This module can be used to visualize the clumps files created by the Meter module.

## Prerequisites

Python packages needed for running DoHlyzer are listed in `requirements.txt` file. You can install them 
(preferably in virtualenv) by:
```
pip install -r requirements.txt
```

## Deployment

Each of the modules come with their own README files to describe how they can be used.

## Contributing

The project is not currently in development but any contribution is welcome in form of pull requests.

## Copyright (c) 2020 

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (DoHLyzer), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
For citation in your works and also understanding DoHLyzer completely, you can find below published paper:

"Detection of DoH Tunnels using Time-series Classification of Encrypted Traffic", Mohammadreza MontazeriShatoori, Logan Davidson, Gurdip Kaur and Arash Habibi Lashkari, The 5th Cyber Science and Technology Congress (2020) (CyberSciTech 2020), Vancouver, Canada, August 2020
```
@INPROCEEDINGS{9251211,
  author={MontazeriShatoori, Mohammadreza and Davidson, Logan and Kaur, Gurdip and Habibi Lashkari, Arash},
  booktitle={2020 IEEE Intl Conf on Dependable, Autonomic and Secure Computing, Intl Conf on Pervasive Intelligence and Computing, Intl Conf on Cloud and Big Data Computing, Intl Conf on Cyber Science and Technology Congress (DASC/PiCom/CBDCom/CyberSciTech)}, 
  title={Detection of DoH Tunnels using Time-series Classification of Encrypted Traffic}, 
  year={2020},
  volume={},
  number={},
  pages={63-70},
  doi={10.1109/DASC-PICom-CBDCom-CyberSciTech49142.2020.00026}}
  ```

## Project Team members

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and Project Leader
* [**Mohammadreza MontazeriShatoori:**](https://github.com/mr-montazeri) Research and Development
* [**Gurdip Kaur:**](https://www.linkedin.com/in/gurdip-kaur-738062164/) Research
* [**Logan Davidson:**](https://github.com/ladavids) Development
