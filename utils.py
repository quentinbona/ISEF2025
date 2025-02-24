import tensorflow as tf
import os

MODEL_PATH = "models/network_traffic_model.h5"

def save_model(model):
    """
    Saves the trained model to a file.
    """
    if not os.path.exists("models"):
        os.makedirs("models")
    model.save(MODEL_PATH)
    print("Model saved successfully.")

def load_model():
    """
    Loads the trained model if it exists.
    """
    if os.path.exists(MODEL_PATH):
        return tf.keras.models.load_model(MODEL_PATH)
    else:
        print("No trained model found.")
        return None
