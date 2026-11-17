from flask import Flask

app = Flask(__name__)

@app.route("/")
def dashboard():
    return """
    <h1>PurpleRecon v2</h1>
    <p>Web platformu başarıyla başlatıldı.</p>
    <p>Status: Development</p>
    """

if __name__ == "__main__":
    app.run(debug=True)