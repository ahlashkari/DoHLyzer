import argparse
import json
import math

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure


class TimeScale:
    def __init__(self):
        self.time = 0

    def move_forward(self, passed):
        passed = max(passed, 1e-4)
        transformed_passed = math.log(passed * 1e5)
        # print(passed, transformed_passed)
        self.time += transformed_passed
        return transformed_passed


class ClumpSequence:
    def __init__(self, title, clumps):
        self.positions = []
        self.widths = []
        self.heights = []
        self.colors = []
        self.axes = None
        self.title = title

        time_scale = TimeScale()

        for c in clumps:
            clump_interarrival, clump_duration, clump_size, clump_packets, clump_direction = c

            time_scale.move_forward(clump_interarrival)
            self.positions.append(time_scale.time)

            width = time_scale.move_forward(clump_duration)
            self.widths.append(width)

            height = clump_size
            self.heights.append(height)

            self.colors.append('green' if clump_direction > 0 else 'red')

    def visualize(self, figure):
        if self.axes is None:
            self.axes: Axes = figure.add_subplot(label=self.title)
        self.axes.bar(
            x=self.positions,
            height=self.heights,
            width=self.widths,
            align='edge',
            color=self.colors
        )
        # print(self.widths)

        self.axes.set_yscale('log')
        self.axes.set_ylim(bottom=50, top=1e4)
        self.axes.set_xlim(left=0, right=500)
        self.axes.set_title(self.title)


def visualize(title, clumps_seq):
    fig: Figure = plt.figure()
    clump_seq = ClumpSequence(title, clumps_seq)
    clump_seq.visualize(fig)
    plt.show()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input')
    args = parser.parse_args()

    f = open(args.input)
    contents = json.load(f)

    visualize(args.input, contents[0])
