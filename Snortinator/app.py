from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

def generate_snort_rule(action, protocol, src_ip, src_port, dst_ip, dst_port, message, content=None, sid=10001, rev=1):
    """
    Generates a Snort rule based on user input.
    """
    rule = f"{action} {protocol} {src_ip} {src_port} -> {dst_ip} {dst_port} (msg:\"{message}\"; sid:{sid}; rev:{rev};"
    if content:
        rule += f" content:\"{content}\";"
    rule += ")"
    return rule

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate_rule", methods=["POST"])
def generate_rule():
    # Extract form data
    data = request.json
    action = data.get("action", "alert")
    protocol = data.get("protocol", "tcp")
    src_ip = data.get("src_ip", "$EXTERNAL_NET")
    src_port = data.get("src_port", "any")
    dst_ip = data.get("dst_ip", "$HOME_NET")
    dst_port = data.get("dst_port", "any")
    message = data.get("message", "Generated Rule")
    content = data.get("content", None)
    sid = data.get("sid", 10001)
    rev = data.get("rev", 1)

    # Generate rule
    rule = generate_snort_rule(action, protocol, src_ip, src_port, dst_ip, dst_port, message, content, sid, rev)
    return jsonify({"rule": rule})

if __name__ == "__main__":
    app.run(debug=True)
