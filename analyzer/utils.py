from itertools import tee, islice

import numpy


def nwise(iterable, n=2):
    iters = tee(iterable, n)
    for i, it in enumerate(iters):
        next(islice(it, i, i), None)
    return zip(*iters)


def combine(*args):
    return numpy.concatenate(tuple(a[0] for a in args)), numpy.concatenate(tuple(a[1] for a in args))


def normalize(data, data_min, data_max):
    return min(1, max(-1, (data - data_min) / (data_max - data_min) * 2 - 1))
