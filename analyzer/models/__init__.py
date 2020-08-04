import importlib


def create_model(version, segment_size):
    module = importlib.import_module('.v{}'.format(version), package='models')
    return module.create_model(segment_size)
