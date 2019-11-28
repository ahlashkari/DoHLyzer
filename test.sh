#!/bin/bash
choice="2"
while getopts 'op' flag; do
	case "${flag}" in
		p) choice="1";;
		o) choice="2" ;;
		*) exit 1 ;;
	esac
done
printf "test2.csv\n$choice" | sudo python3 dohlyzer.py
wait
xdg-open test2.csv &
sleep 5
dialogue="Text Import \- \[test2.csv\]"
xdotool key --window "$dialogue" Return