from flask import Flask

# Create the web host app
app = Flask(__name__)

# this route is for our homepage
@app.route("/")
def home():
    return "Welcome to the Home Page!"

# Start the web app.
app.run(debug=True, port=5000)
