FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV SECUREAI_DB_PATH=/tmp/secureai.db
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
