from kryptoflask import app

app.config['TESTING'] = True

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)