FROM python:3.11-slim

WORKDIR /app

# install OS deps if sqlmap required (OPTIONAL)
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# If your app requires env PORT variable
ENV PORT=5000
EXPOSE 5000

# Ensure your app listens on 0.0.0.0 and uses the PORT env var
CMD ["sh", "-c", "python app.py"]
