from flask import Flask, render_template, request, redirect, url_for, send_file, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw, ImageFont
from barcode import Code128
from barcode.writer import ImageWriter
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import mm
from reportlab.lib.utils import ImageReader
import qrcode
import sqlite3
from functools import wraps

import pandas as pd
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.graphics.barcode import code128
from reportlab.lib.units import mm
from io import BytesIO
from random import choice
import random, string


def gen(length=5):
    # Генерируем случайную строку из букв (как заглавных, так и строчных)
    letters = string.ascii_letters  # 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.choice(letters) for _ in range(length))

app = Flask(__name__)
app.secret_key = 'secret_key'

# Настройки для админа
ADMIN_PASSWORD = 'root'
ADMIN_USERNAME = 'root'

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Создаем таблицу пользователей, если её нет
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Проверяем, существует ли уже администратор
    c.execute('SELECT * FROM users WHERE username = ?', (ADMIN_USERNAME,))
    admin = c.fetchone()

    # Если нет, то создаем администратора
    if admin is None:
        hashed_password = generate_password_hash(ADMIN_PASSWORD)
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (ADMIN_USERNAME, hashed_password))
        conn.commit()

    conn.close()


# Проверка, авторизован ли пользователь
def login_required(f):
    @wraps(f)  # Сохраняем оригинальное имя функции
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Функция для проверки, является ли пользователь администратором
def is_admin():
    return session.get('is_admin')

# Маршрут для страницы администрирования
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not is_admin():
        flash('Доступ запрещён: только администратор может зайти на эту страницу.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']


        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        hashed_password = generate_password_hash(password)  # Хэшируем пароль
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()

        flash(f'Пользователь {username} успешно создан.')
        return redirect(url_for('admin'))

    return render_template('admin.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form['password']


        if password == ADMIN_PASSWORD:
            session['is_admin'] = True
            flash('Вы вошли как администратор.')
            return redirect(url_for('admin'))
        else:
            flash('Неверный пароль администратора.')

    return render_template('login.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/admin_logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Вы вышли из системы администратора.')
    return redirect(url_for('admin_login'))



@app.route('/generate', methods=['POST'])
@login_required
def generate():
    # Получаем данные из формы
    barcode_data = request.form['barcode']
    article = request.form['article']
    seller = request.form['seller']
    color = request.form['color']
    size = request.form['size']
    product_name = request.form['product_name']
    quantity = int(request.form['quantity'])
    use_qrcode = 'use_qrcode' in request.form


    label_width = 580
    label_height = 400
    barcode_width = 570
    barcode_height = 150
    qr_size = 200

    label = Image.new('RGB', (label_width, label_height), 'white')
    draw = ImageDraw.Draw(label)


    if use_qrcode:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(barcode_data)
        qr.make(fit=True)

        qr_img = qr.make_image(fill='black', back_color='white')
        qr_img = qr_img.resize((qr_size, qr_size))
        label.paste(qr_img, (170, 1))
    else:
        barcode = Code128(barcode_data, writer=ImageWriter())
        barcode_buffer = BytesIO()
        barcode.write(barcode_buffer)
        barcode_buffer.seek(0)
        barcode_image = Image.open(barcode_buffer)
        barcode_image = barcode_image.resize((barcode_width, barcode_height))
        label.paste(barcode_image, (0, 10))


    label_text = (
        f"{seller}\n"
        f"{product_name}\n"
        f"Артикул: {article}\n"
        f"Цв.: {color} / Раз.: {size}\n"
    )


    font_size = 24
    font = ImageFont.truetype("arial.ttf", font_size)
    text_y = barcode_height + 30
    text_lines = label_text.split('\n')
    for line in text_lines:
        while True:
            text_bbox = draw.textbbox((0, 0), line, font=font)
            text_width = text_bbox[2] - text_bbox[0]
            if text_width <= label_width:
                break
            font_size -= 1
            font = ImageFont.truetype("arial.ttf", font_size)

        text_x = (label_width - text_width) // 2
        draw.text((text_x, text_y), line, fill="black", font=font)
        text_y += 40

    img_io = BytesIO()
    label.save(img_io, 'PNG')
    img_io.seek(0)

    # Создание PDF
    pdf_io = BytesIO()
    label_page_size = (58 * mm, 40 * mm)

    c = canvas.Canvas(pdf_io, pagesize=label_page_size)
    img_reader = ImageReader(img_io)
    for _ in range(quantity):
        c.drawImage(img_reader, 0, 0, width=58 * mm, height=40 * mm)
        c.showPage()

    c.save()
    pdf_io.seek(0)
    cd = gen(5)
    return send_file(pdf_io, as_attachment=True, download_name=f"{cd}.pdf", mimetype='application/pdf')


#Стандартный вход 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user'] = user[1]
            return redirect(url_for('index'))
        else:
                return render_template('error.html')

    return render_template('login.html')



@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    username = session.get('user') 
    print(username)

    if username == "root":
        if request.method == 'POST':
            new_username = request.form['username']
            password = request.form['password']

            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            
            try:
                hashed_password = generate_password_hash(password)
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (new_username, hashed_password))
                conn.commit()
                flash(f'Пользователь {new_username} успешно создан.')
            except sqlite3.IntegrityError:
                flash(f'Ошибка: пользователь с именем {new_username} уже существует.')
            finally:
                conn.close()
            return redirect(url_for('add_user'))

        return render_template('add_user.html')
    
    # Если пользователь не root, перенаправляем на главную страницу или показываем сообщение
    flash('Доступ запрещён: только администратор может добавлять пользователей.')
    return redirect(url_for('index'))  # или вы можете перенаправить на другую страницу

from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFont
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from io import BytesIO
import pandas as pd
import os

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xlsx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Route for uploading Excel file and entering seller name
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        # Check if file part is in the request
        if 'file' not in request.files:
            flash('No file part in the request')
            return redirect(request.url)
        
        file = request.files['file']
        seller_name = request.form.get('seller_name', '').strip()
        
        # Check for empty filename or invalid file type
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash('Invalid file type. Only .xlsx files are allowed.')
            return redirect(request.url)
        
        if not seller_name:
            flash('Please enter a seller name')
            return redirect(request.url)
        
        # Secure the filename and save the file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(file_path)
        except PermissionError:
            flash('Permission denied: Unable to save the uploaded file.')
            return redirect(request.url)
        except Exception as e:
            flash(f'An error occurred while saving the file: {str(e)}')
            return redirect(request.url)
        
        try:
            # Generate PDF with labels
            pdf_data = generate_labels_pdf(file_path, seller_name)
        except KeyError as ke:
            flash(str(ke))
            return redirect(request.url)
        except Exception as e:
            flash(f'An error occurred during PDF generation: {str(e)}')
            return redirect(request.url)
        
        # Optionally, delete the uploaded file after processing
        try:
            os.remove(file_path)
        except Exception as e:
            print(f'Error deleting file: {str(e)}')
        
        cd = gen(5)
        return send_file(pdf_data, as_attachment=True, download_name=f"{cd}.pdf", mimetype='application/pdf')
    
    return render_template('upload.html')

# Function to generate labels PDF from Excel data with barcodes

def generate_labels_pdf(excel_path, seller_name, quantity=1, use_qrcode=False):
    try:
        # Load the Excel data
        data = pd.read_excel(excel_path)
    except PermissionError:
        raise PermissionError("Unable to access the Excel file. Please ensure it's not open elsewhere.")
    except Exception as e:
        raise Exception(f"Error reading Excel file: {str(e)}")
    
    # Clean up column names by removing any leading or trailing whitespace
    data.columns = data.columns.str.strip()
    print("Column names in Excel file:", list(data.columns))

    # Define required columns
    required_columns = ['Наименование', 'Цвет', 'Размер', 'Артикул продавца', 'Баркод']
    missing_columns = [col for col in required_columns if col not in data.columns]
    
    if missing_columns:
        raise KeyError(f"Missing columns in Excel file: {', '.join(missing_columns)}")
    
    # Create a PDF buffer in memory
    pdf_buffer = BytesIO()
    label_page_size = (58 * mm, 40 * mm)
    c = canvas.Canvas(pdf_buffer, label_page_size)
    width, height = A4
    label_width = 580  # Width for label
    label_height = 400  # Height for label
    barcode_width = 570
    barcode_height = 150
    qr_size = 200

    # Loop through the rows and create labels
    for index, row in data.iterrows():
        # Retrieve product details from the row
        item_name = row.get('Наименование', 'N/A')
        color = row.get('Цвет', 'N/A')
        size = row.get('Размер', 'N/A')
        article = row.get('Артикул продавца', 'N/A')
        barcode_value = str(row.get('Баркод', 'N/A'))

        # Create an image for the label
        label = Image.new('RGB', (label_width, label_height), 'white')
        draw = ImageDraw.Draw(label)

        if use_qrcode:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(barcode_value)
            qr.make(fit=True)
            qr_img = qr.make_image(fill='black', back_color='white')
            qr_img = qr_img.resize((qr_size, qr_size))
            label.paste(qr_img, (170, 1))
        else:
            barcode = Code128(barcode_value, writer=ImageWriter())
            barcode_buffer = BytesIO()
            barcode.write(barcode_buffer)
            barcode_buffer.seek(0)
            barcode_image = Image.open(barcode_buffer)
            barcode_image = barcode_image.resize((barcode_width, barcode_height))
            label.paste(barcode_image, (0, 10))

        # Prepare the label text
        label_text = (
            f"{seller_name}\n"
            f"{item_name}\n"
            f"Артикул: {article}\n"
            f"Цв.: {color} / Раз.: {size}\n"
        )

        font_size = 24
        font = ImageFont.truetype("arial.ttf", font_size)
        text_y = barcode_height + 30
        text_lines = label_text.split('\n')
        for line in text_lines:
            while True:
                text_bbox = draw.textbbox((0, 0), line, font=font)
                text_width = text_bbox[2] - text_bbox[0]
                if text_width <= label_width:
                    break
                font_size -= 1
                font = ImageFont.truetype("arial.ttf", font_size)

            text_x = (label_width - text_width) // 2
            draw.text((text_x, text_y), line, fill="black", font=font)
            text_y += 40

        # Save label to a buffer for PDF embedding
        img_io = BytesIO()
        label.save(img_io, 'PNG')
        img_io.seek(0)

        # Create a PDF page for the label
        img_reader = ImageReader(img_io)
        label_page_size = (58 * mm, 40 * mm)  # PDF page size for label
        c.drawImage(img_reader, 0, 0, width=58 * mm, height=40 * mm)

        # Add additional pages if quantity is more than 1
        for _ in range(quantity - 1):
            c.showPage()
            c.drawImage(img_reader, 0, 0, width=58 * mm, height=40 * mm)

        c.showPage()  # Move to the next page for the next label

    # Save and close the PDF
    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))




if __name__ == '__main__':
    init_db()
    app.run(debug=True, host="62.109.1.99", port=80)
