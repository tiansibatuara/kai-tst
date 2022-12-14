# Menginstall base image
FROM python:3.9-alpine

# Mengganti workdir
WORKDIR /app

# Melakukan copy file di folder ini menuju folder /app di container
COPY . /app

# Melakukan upgrade pip untuk memastikan semua requirements dapat terinstall
RUN python -m pip install --upgrade pip

# Menginstall semua requirement yang dibutuhkan
RUN pip install -r requirements.txt

# Membuka port 8000 agar dapat diakses dari luar container
EXPOSE 5000

# Menjalankan main.py
CMD [ "flask", "run", "--host=0.0.0.0", "--port=5000" ]