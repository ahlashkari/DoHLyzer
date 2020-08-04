# Visualizer
This module can be used to visualize JSON clumps files created by the Meter module.

Since visualizing network traffic can be challenging, this module comes up with a couple of changes to make the visualization more meaningful.

Clumps are shown in a bar chart with X axis showing the time difference, and Y axis showing the size of clumps. Outgoing clumps are shown in green and incoming clumps are depicted red. The Y axis (size of clumps) is in a logarithmic scale to allow for clumps of all sizes to be visible in a single chart.

The X axis (time difference) is more complicated. We are using a logarithmic transformation here too, but not for the whole scale, only the distances between clumps (and the width of the clumps).

## Usage
To use this module you could just run `main.py` with the path of input file as a shell argument.

Example:
```bash
python visualizer/main.py visualizer/examples/google-doh-footprint.json
```
