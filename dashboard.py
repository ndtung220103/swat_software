from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app) 

sensor_value = {}
metrics_store = {}

@app.route('/metrics', methods=['POST'])
def receive_metrics():
    global metrics_store
    data = request.get_json()
    if data:
        metrics_store = data
        print("Received metrics:", metrics_store)
        return jsonify({"status": "success"}), 200
    return jsonify({"error": "No data"}), 400

@app.route('/metrics', methods=['GET'])
def dashboard():
    return jsonify(metrics_store)

@app.route('/sensors', methods=['POST'])
def receive_sensors():
    data = request.get_json()
    sensor_value.update(data)
    return jsonify({"status": "ok"}), 200

@app.route('/sensors', methods=['GET'])
def get_sensors():
    return jsonify(sensor_value)  

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
