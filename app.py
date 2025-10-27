from flask import Flask, render_template, redirect, url_for, abort

app = Flask(__name__, static_folder='static', static_url_path='/')

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/panel')
def panel():
    return render_template('index.html')

ALLOWED_PAGES = {
    'index', 'blank', 'button', 'chart', 'element',
    'form', 'signin', 'signup', 'table', 'typography',
    'widget', '404'
}

@app.route('/<page>.html')
def page_with_ext(page):
    if page in ALLOWED_PAGES:
        return render_template(f'{page}.html')
    abort(404)

@app.route('/<page>')
def page_without_ext(page):
    if page in ALLOWED_PAGES:
        return redirect(url_for('page_with_ext', page=page))
    abort(404)

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)
