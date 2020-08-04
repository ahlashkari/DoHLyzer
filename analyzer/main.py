#!/usr/bin/env python3
import argparse
import json
import logging

from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.callbacks import EarlyStopping

import analyzer.dataset as dataset
from analyzer.models import create_model


def run_model(version, segment_size):
    model = create_model(version, segment_size)

    print(model.summary())

    es = EarlyStopping()

    model.fit(x_train, y_train, epochs=100, validation_data=(x_test, y_test), callbacks=[es],
              batch_size=32)

    y_pred = model.predict(x_test, verbose=1)
    y_pred_bool = list(map(lambda y: 1 if y > 0.5 else 0, y_pred))

    return (
        classification_report(y_test, y_pred_bool, digits=5, output_dict=True),
        confusion_matrix(y_test, y_pred_bool).tolist()
    )


if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S')

    parser = argparse.ArgumentParser()
    parser.add_argument('--input', help='input directory containing aggregated clumps files',
                        default='./sample_data')
    parser.add_argument('--output', help='output file',
                        default='./sample_data/output.json')
    args = parser.parse_args()

    results = []

    for segment_size in range(4, 11):

        x_train, x_test, y_train, y_test = dataset.load_dataset(args.input, segment_size, use_cache=False)

        for model_idx in range(1, 5):
            for _ in range(3):
                results.append((run_model(model_idx, segment_size), model_idx, segment_size))

    output = open(args.output, 'w')

    for res, model_idx, segments in results:
        print('=' * 20 + ' [SEG={}] Model {} '.format(segments, model_idx) + '=' * 20)
        print(res[0])
        print(res[1])

    json.dump(results, output)
    output.close()
