
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install gunicorn

COPY . .

EXPOSE 10000

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT --workers 1 --timeout 120 app:app"]
