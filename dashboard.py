from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app) 

data_store = {}  # key = "srcip->dstip", value = {...}
sensor_value = {}

@app.route('/metrics', methods=['POST'])
def receive_metrics():
    data = request.get_json()
    key = f"{data['srcip']}->{data['dstip']}"
    data_store[key] = data
    return jsonify({"status": "ok"}), 200

@app.route('/metrics', methods=['GET'])
def get_metrics():
    return jsonify(list(data_store.values()))  

@app.route('/sensors', methods=['POST'])
def receive_sensors():
    data = request.get_json()
    sensor_value.update(data)
    print(f"[RECEIVED] {data}")
    return jsonify({"status": "ok"}), 200

@app.route('/sensors', methods=['GET'])
def get_sensors():
    return jsonify(sensor_value)  

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
