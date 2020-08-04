from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM, Conv1D, MaxPool1D, Flatten


def create_model(segment_size):
    model = Sequential()
    model.add(Conv1D(segment_size * 2, kernel_size=3, input_shape=(segment_size, 5), activation='relu'))
    model.add(MaxPool1D())
    model.add(Flatten())
    model.add(Dense(segment_size * 6, activation='relu'))
    model.add(Dropout(0.2))
    model.add(Dense(segment_size * 2, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))
    model.compile(loss='binary_crossentropy', optimizer='adam',
                  metrics=['accuracy'])
    return model
