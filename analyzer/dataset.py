import gzip
import logging
import math
import os
import pickle

import ijson
import numpy
from sklearn.model_selection import train_test_split

import analyzer.utils as utils


def create_segments(clumps_list, segment_size):
    clumps_list2 = []
    # Inter-arrival, Duration, Size, Packets, Direction
    for c in clumps_list:
        c2 = [
            utils.normalize(math.log10(max(1e-12, c[0])), data_min=-12, data_max=-2),
            utils.normalize(math.log10(max(1e-12, c[1])), data_min=-12, data_max=-2),
            utils.normalize(math.log10(min(1e4, c[2])), data_min=0.5, data_max=4),
            utils.normalize(math.log2(min(256, c[3])), data_min=0, data_max=8),
            c[4]
        ]
        clumps_list2.append(c2)

    while len(clumps_list2) < segment_size:
        clumps_list2.append([-1, -1, -1, -1, 0])

    return utils.nwise(clumps_list2, segment_size)


def load_json(path, label, segment_size, shuffle=True, max_count=0):
    logging.info('Loading {} .'.format(path))
    if path.endswith('gz'):
        json_file = gzip.open(path, 'r')
    else:
        json_file = open(path, 'r')
    logging.info('Loading {} ..'.format(path))

    items = ijson.items(json_file, 'item')

    segments = []

    for flow in items:
        if 0 < max_count < len(segments):
            break
        segments.extend(create_segments(flow, segment_size))

    logging.info('Loading {} ...'.format(path))

    if shuffle:
        numpy.random.shuffle(segments)

    return numpy.array(segments), numpy.full(len(segments), label)


def load_dataset(dir_path, segment_size, use_cache=True):
    cache_path = os.path.join(dir_path, 'cache-{}'.format(segment_size))
    if use_cache and os.path.exists(cache_path):
        print('Using cached version')
        return pickle.load(open(cache_path, 'rb'))

    doh_dataset = load_json(os.path.join(dir_path, 'doh.json.gz'), 1, segment_size)
    ndoh_dataset = load_json(os.path.join(dir_path, 'ndoh.json.gz'), 0, segment_size, max_count=len(doh_dataset[0]))

    logging.info('Combining datasets')
    main_dataset = utils.combine(doh_dataset, ndoh_dataset)

    logging.info('Splitting test/train')
    dataset_tuple = train_test_split(*main_dataset)

    if use_cache:
        pickle.dump(dataset_tuple, open(cache_path, 'wb'))

    return dataset_tuple
