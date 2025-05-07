from flask import Flask, request, jsonify

app = Flask(__name__)
data_store = []

@app.route('/metrics', methods=['POST'])
def receive_metrics():
    data = request.get_json()
    data_store.append(data)
    print(f"Received: {data}")
    return jsonify({"status": "ok"}), 200

@app.route('/metrics', methods=['GET'])
def get_metrics():
    return jsonify(data_store)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
