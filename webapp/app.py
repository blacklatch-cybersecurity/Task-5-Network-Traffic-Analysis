# webapp/app.py
from flask import Flask, render_template, request, redirect, url_for
from scanner.scanner import crawl_and_scan
import os, json
app = Flask(__name__, template_folder='templates')

# In-memory or file-based store
RESULTS_FILE = os.path.join(os.path.dirname(__file__), "last_results.json")

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    max_pages = int(request.form.get('max_pages', 20))
    results = crawl_and_scan(url, max_pages=max_pages)
    # save
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    return render_template('results.html', results=results)

@app.route('/last', methods=['GET'])
def last():
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            results = json.load(f)
        return render_template('results.html', results=results)
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
