FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

ENV PORT=6000
EXPOSE 6000

CMD ["sh", "-c", "python xss_app.py"]
