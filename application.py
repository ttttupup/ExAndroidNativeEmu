from flask import Flask, request, json, Response, jsonify
import jd_sign
import time
import threading
import os
import random

import uuid

app = Flask(__name__)
app.config.from_pyfile("ip.cfg")
jd = jd_sign.JdSign()
value_lock = threading.Lock()
ips = app.config.get("WHITE_IP")
white_ip_list = []
for ip in ips:
    white_ip_list.append(ip)


@app.route('/')
def index():
    return "200"


@app.route('/updateIp', methods=['POST'])
def update_ip():
    data = request.get_data()
    json_data = json.loads(data.decode("utf-8"))
    ip_add = json_data.get("ip")
    result = {
        "code": 200,
        "ip": ip_add
    }
    if ip_add.strip() == "":
        return jsonify(result)
    white_ip_list.append(ip_add)
    return jsonify(result)


@app.route('/upload', methods=['POST'])
def upload():
    result = {
        "code": 400,
    }
    if 'file' not in request.files:
        return jsonify(result)
    file = request.files['file']
    base_path = os.path.abspath('.')
    upload_path = os.path.join(base_path, 'account', file.filename + "." + str(int(time.time())) + ".log")
    file.save(upload_path)
    result = {
        "code": 200,
    }
    return jsonify(result)


@app.route('/sign', methods=['POST'])
def get_sign():
    """
    data = {
        "childActivityUrl": "openapp.jdmobile://virtual?params={\"category\":\"jump\",\"des\":\"couponCenter\"}",
        "couponKey": "aa641ae6effb4123ad842bf771ab114b",
        "ruleId": 55865284,
        "receiveType": 1
    }
    """
    start = time.time()
    real_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if real_ip not in white_ip_list:
        error_result = {
            "sign": "&st=%d&sign=%s&sv=%d" % (start, uuid.uuid1().hex, random.randrange(110, 113))
        }
        return jsonify(error_result)

    data = request.get_data()
    json_data = json.loads(data.decode("utf-8"))
    function_id = json_data.get("functionId")
    device_id = json_data.get("deviceId")
    body = json_data.get("body")
    result = {
        "code": 400,
        "message": "参数错误"
    }
    if function_id.strip() == "":
        return jsonify(result)
    if device_id.strip() == "":
        return jsonify(result)
    if body.strip() == "":
        return jsonify(result)

    with value_lock:
        sign = jd.hook_sign(function_id, device_id, body)
    response = {
        "sign": sign
    }
    end = time.time()
    print(end - start)
    return Response(json.dumps(response), mimetype='application/json')


if __name__ == '__main__':
    app.run(debug=True)
