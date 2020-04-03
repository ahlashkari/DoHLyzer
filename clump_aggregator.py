#!/usr/bin/env python3

import argparse
import json
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input_dir')
    args = parser.parse_args()
    path = args.input_dir
    files = (os.path.join(path, f) for f in os.listdir(path) if f.endswith(".json") and not f == 'all.json')
    contents = list()
    for p in files:
        f = open(p, 'r')
        f_c = json.load(f)
        contents.extend(f_c)
        print(p)

    out = open(os.path.join(path, 'all.json'), 'w')
    json.dump(contents, out, indent=2)
