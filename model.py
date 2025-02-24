import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split


def build_model(input_shape):
    """
    Builds a simple deep-learning model for network packet classification.
    """
    model = Sequential([
        Dense(64, activation='relu', input_shape=(input_shape,)),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.2),
        Dense(2, activation='softmax')  # 2 classes (benign vs. malicious)
    ])

    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model


def train_model(X, y):
    """
    Trains the deep-learning model using extracted features.
    """
    # Normalize feature values
    X = X / np.max(X, axis=0)

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Convert labels to categorical
    y_train = to_categorical(y_train, num_classes=2)
    y_test = to_categorical(y_test, num_classes=2)

    model = build_model(X.shape[1])

    # Train the model
    model.fit(X_train, y_train, epochs=30, batch_size=16, validation_data=(X_test, y_test))

    # Evaluate model performance
    loss, accuracy = model.evaluate(X_test, y_test)
    print(f"Model Accuracy: {accuracy:.4f}")

    return model
