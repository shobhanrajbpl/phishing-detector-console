import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

data = {
    "url_length": [20, 120, 35, 90, 50],
    "has_ip": [0, 1, 0, 1, 0],
    "num_dots": [1, 5, 2, 6, 2],
    "https": [1, 0, 1, 0, 1],
    "label": [0, 1, 0, 1, 0]
}

df = pd.DataFrame(data)

X = df.drop("label", axis=1)
y = df["label"]

model = RandomForestClassifier()
model.fit(X, y)

with open("phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained and saved.")
