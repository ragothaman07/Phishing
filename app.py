from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from features import featureExtraction

app = Flask(__name__, static_folder="dist", template_folder="dist")

CORS(app)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get("url")
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        features = featureExtraction(url)
        phishing_score = sum(features) / len(features)
        is_phishing = phishing_score > 0.5

        response = {
            "url": url,
            "is_phishing": is_phishing,
            "probability": phishing_score,
            "features": {f"feature_{i+1}": val for i, val in enumerate(features)}
        }
        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Serve React build
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, "index.html")


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
