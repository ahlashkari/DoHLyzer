#!/bin/bash
choice="2"
interf="2"
file=" "

while getopts 'op123' flag; do
	case "${flag}" in
		p) choice="1" ;;
		o) choice="2" ;;
		1) interf="1" ;;
		2) interf="2" ;;
		3) interf="3" ;;
		*) exit 1 ;;
	esac
done
if [ choice=2 ] 
then
	file="test2.csv"
	printf "$file\n$choice\n$interf" | sudo python3 dohlyzer.py
else
	file="test.csv"
	printf "$file\n$choice" | python3 dohlyzer.py
fi

wait
xdg-open $file &
sleep 5
dialogue="Text Import \- \[$file\]"
xdotool key --window "$dialogue" Return