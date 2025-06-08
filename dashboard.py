from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app) 

sensor_value = {}
metrics_store = {}
received_port_stats = {}
received_flow_stats = {}
list_mess = {}

@app.route('/port_stats', methods=['POST'])
def receive_port_stats():
    global received_port_stats
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400
    received_port_stats = data
    print("[Dashboard] Received port stats.")
    return jsonify({"status": "received port stats"}), 200

@app.route('/flow_stats', methods=['POST'])
def receive_flow_stats():
    global received_flow_stats
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400
    received_flow_stats = data
    print("[Dashboard] Received flow stats.")
    return jsonify({"status": "received flow stats"}), 200

@app.route('/get_port_stats')
def get_port_stats():
    return jsonify(received_port_stats)

@app.route('/get_flow_stats')
def get_flow_stats():
    return jsonify(received_flow_stats)

@app.route('/metrics', methods=['POST'])
def receive_metrics():
    global metrics_store
    data = request.get_json()
    if data:
        metrics_store = data
        return jsonify({"status": "success"}), 200
    return jsonify({"error": "No data"}), 400

@app.route('/metrics', methods=['GET'])
def dashboard():
    return jsonify(metrics_store)

@app.route('/sensors', methods=['POST'])
def receive_sensors():
    data = request.get_json()
    sensor_value.update(data)
    print(sensor_value)
    return jsonify({"status": "ok"}), 200

@app.route('/sensors', methods=['GET'])
def get_sensors():
    return jsonify(sensor_value)  

@app.route('/mess', methods=['POST'])
def receive_mess():
    data = request.get_json()
    list_mess.update(data)
    print(list_mess)
    return jsonify({"status": "ok"}), 200

@app.route('/mess', methods=['GET'])
def get_mess():
    return jsonify(list_mess) 

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
