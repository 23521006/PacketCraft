from flask import Flask, jsonify, request
from scapy import *

app = Flask(__name__)

@app.route('/interfaces', methods=['GET'])
def get_interfaces_api():
    try:
        
        return jsonify({
            "status": "success",
            "interfaces": interfaces
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500