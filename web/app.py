from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_sock import Sock
from datetime import datetime, timedelta
import os
import json
import bcrypt
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_sock import Sock
from datetime import datetime, timedelta
import os
import json
import bcrypt
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gym.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)
sock = Sock(app)

# نموذج قاعدة البيانات
class Gym(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # إزالة default عشان تحدد الـ ID يدويًا
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)



class ActivationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gym_id = db.Column(db.String(36), db.ForeignKey('gym.id'), nullable=False)
    code = db.Column(db.String(50), nullable=False, unique=True)
    subscription_type = db.Column(db.String(10), nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    payment_receipt = db.Column(db.String(200))
    payment_phone = db.Column(db.String(20))
    payment_confirmed = db.Column(db.Boolean, default=False)

# عمل قاعدة البيانات
with app.app_context():
    db.create_all()

# قائمة بالعملاء المتصلين عبر WebSocket
connected_clients = {}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        gym_id = request.form['gym_id']
        password = request.form['password'].encode()
        gym = Gym.query.filter_by(id=gym_id).first()
        if gym and bcrypt.checkpw(password, gym.password.encode()):
            active_code = ActivationCode.query.filter_by(gym_id=gym_id, is_active=True).first()
            if active_code and active_code.expiry_date > datetime.now():
                return render_template('welcome.html', gym_name=gym.name, subscription=active_code.subscription_type, expiry=active_code.expiry_date)
            else:
                flash('No active activation code. Please purchase one.')
                return redirect(url_for('purchase'))
        else:
            flash('Invalid Gym ID or password.')
    return render_template('login.html')

@app.route('/purchase', methods=['GET', 'POST'])
def purchase():
    if request.method == 'POST':
        gym_id = request.form['gym_id']
        subscription_type = request.form['subscription_type']
        payment_method = request.form['payment_method']
        payment_phone = request.form['payment_phone']
        receipt = request.files['receipt']
        if receipt:
            receipt_path = os.path.join(app.config['UPLOAD_FOLDER'], receipt.filename)
            receipt.save(receipt_path)
            code = str(uuid.uuid4())[:8]
            expiry = datetime.now() + timedelta(days=365 if subscription_type.startswith('Y') else 30)
            new_code = ActivationCode(
                gym_id=gym_id,
                code=code,
                subscription_type=subscription_type,
                expiry_date=expiry,
                payment_receipt=receipt_path,
                payment_phone=payment_phone
            )
            db.session.add(new_code)
            db.session.commit()
            flash('Payment submitted. Waiting for admin confirmation.')
            return redirect(url_for('login'))
    return render_template('purchase.html', subscriptions=['Y1', 'Y2', 'Y3', 'Y4', 'Y5'])

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        if 'add_gym' in request.form:
            gym_id = request.form['gym_id']
            name = request.form['gym_name']
            password = bcrypt.hashpw(request.form['gym_password'].encode(), bcrypt.gensalt()).decode()
            # التأكد إن الـ ID مش موجود قبل كده
            if Gym.query.get(gym_id):
                flash('Gym ID already exists!')
            else:
                gym = Gym(id=gym_id, name=name, password=password)
                db.session.add(gym)
                db.session.commit()
                flash(f'Gym added successfully! Gym ID: {gym_id}')
        elif 'confirm_payment' in request.form:
            code_id = request.form['code_id']
            code = ActivationCode.query.get(code_id)
            code.payment_confirmed = True
            code.is_active = True
            db.session.commit()
            if code.gym_id in connected_clients:
                connected_clients[code.gym_id].send(json.dumps({
                    'gym_id': code.gym_id,
                    'code': code.code,
                    'subscription_type': code.subscription_type,
                    'expiry_date': code.expiry_date.isoformat()
                }))
            flash('Payment confirmed and code activated!')
    gyms = Gym.query.all()
    codes = ActivationCode.query.all()
    return render_template('admin.html', gyms=gyms, codes=codes)


@app.route('/delete_gym', methods=['POST'])
def delete_gym():
    gym_id = request.form['gym_id']
    gym = Gym.query.get(gym_id)
    if gym:
        db.session.delete(gym)
        db.session.commit()
        flash('Gym deleted successfully!')
    else:
        flash('Gym not found!')
    return redirect(url_for('admin'))



@sock.route('/ws')
def websocket(ws):
    gym_id = ws.environ.get('HTTP_X_GYM_ID')
    if gym_id:
        connected_clients[gym_id] = ws
        try:
            while True:
                ws.receive()
        except:
            del connected_clients[gym_id]

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=True, host='0.0.0.0', port=port)
