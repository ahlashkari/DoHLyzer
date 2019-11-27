#!/bin/bash

echo "test2.csv" | sudo python3 dohlyzer.py
wait
xdg-open test2.csv
