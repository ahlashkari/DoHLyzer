# DoH Analyzer
This module uses the aggregated json files that contain clumps sequences to create DNN models.
4 models are created and benchmarked using the data. The results from the models are written in a JSON file.

## Usage
There are two options that you can specify: input directory and output path.

Input directory can be specified by `--input <input_dir>` and output path by `--output <output_path>`. 

Example:
```bash
PYTHONPATH=../ python3 main.py --input analyzer/sample_data/ --output test.json
```
