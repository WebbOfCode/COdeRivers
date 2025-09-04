from flask import Flask
app = Flask(__name__)
@app.get("/")
def home():
    return "Hello from Safe-URL-Check!"
if __name__ == "__main__":
    app.run()
